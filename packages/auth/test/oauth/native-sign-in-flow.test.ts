import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import { it } from "@effect/vitest";
import { Auth, AuthContract, OAuth, Operations, Sessions } from "@yielded/auth";
import { coordinateCommit, LifecycleHooks } from "@yielded/auth/Hooks";
import type { AuthCredentialCommand, CredentialSlot } from "@yielded/auth/Operations";
import { SubjectId, TokenDigest } from "@yielded/auth/Schema";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import { describe, expect } from "vite-plus/test";

// Human-requested seam: native sign-in through public AuthContract actions and the
// composed Auth service, with a substituted provider protocol and in-memory persistence.
// Failure inventory:
// 1. A new identity yields RegistrationRequired; registration authenticates its subject;
//    a returning identity authenticates the same subject.
// 2. Completion requires the flow's request binding and consumes nothing without it.
// 3. A native flow cannot be completed through the web callback, nor a web flow natively.

const Registration = Schema.Struct({ displayName: Schema.String });

const contract = AuthContract.make("test/native", {
  claims: Schema.Struct({ displayName: Schema.String }),
  actions: (sessions) => ({
    signIn: AuthContract.oauthSignIn(),
    completeSignIn: AuthContract.oauthCompleteSignIn(sessions),
    nativeSignIn: AuthContract.oauthNativeSignIn(),
    completeNativeSignIn: AuthContract.oauthCompleteNativeSignIn(sessions),
    register: AuthContract.oauthRegister(sessions, Registration, { authenticate: true }),
  }),
});

const App = Auth.make(contract, {
  sessions: Sessions.stateless(),
  strategies: {
    apple: OAuth.makeRegistration({
      registration: Registration,
      registrationPolicy: {
        lifetimeMillis: 300_000,
        maximumVerificationAgeMillis: 300_000,
        retentionMillis: 600_000,
      },
      authenticate: true,
    }),
  },
  defaultStrategy: "apple",
});

const strategy = App.strategies.apple;
const issuer = OAuth.OAuthIssuer.make("https://appleid.apple.com");
const provider = OAuth.OAuthProviderKey.make("apple");
// Canonical base64url of 32 bytes, as the transaction protector requires.
const nonce = `${"N".repeat(42)}A`;
const state = `${"S".repeat(42)}A`;

const keyring = {
  activeKeyId: "test",
  keys: [{ id: "test", material: Redacted.make("A".repeat(43)) }],
};

const requirement = Sessions.AuthenticationRequirement.make({
  alternatives: [
    {
      factors: ["possession"],
      minimumCredentials: 1,
      userVerified: false,
      phishingResistant: false,
    },
  ],
  maximumAgeMillis: 300_000,
});

const journal = {
  prepare: <A>(value: A) => ({ _tag: "PreparedCommit" as const, read: Effect.succeed(value) }),
  stage: () => undefined,
};

const harness = Effect.fnUntraced(function* () {
  const flows = new Map<string, OAuth.OAuthSignInFlow>();
  const credentials = new Map<string, OAuth.OAuthCredentialSnapshot>();
  const intents = new Map<string, OAuth.OAuthRegistrationIntent>();
  const exchanges: Array<string> = [];
  let consumed = 0;

  const persistence = Layer.succeed(OAuth.OAuthSignInPersistence, {
    issue: (flow, prepare) =>
      Effect.sync(() => {
        if (flows.has(flow.context.flowId)) return prepare({ _tag: "Rejected" }, journal);
        flows.set(flow.context.flowId, flow);

        return prepare({ _tag: "Issued", flow }, journal);
      }),
    consume: (access, prepare) =>
      Effect.sync(() => {
        const flow = flows.get(access.flowId);
        const context = flow?.context;

        if (
          flow === undefined ||
          context === undefined ||
          context.moduleId !== access.moduleId ||
          context.provider !== access.provider ||
          context.callbackId !== access.callbackId ||
          context.stateDigest !== access.stateDigest ||
          context.requestBindingVerifier !== access.requestBindingVerifier ||
          (access.responseIssuer === undefined) !== (context.responseIssuerMode === "unsupported")
        )
          return prepare({ _tag: "Rejected" }, journal);
        flows.delete(access.flowId);
        consumed++;

        return prepare({ _tag: "Consumed", flow }, journal);
      }),
    resolve: ({ identity }) => Effect.succeed(credentials.get(identity.subject)),
    cleanup: () => Effect.die("unused"),
  });

  const registrationIntents = Layer.succeed(OAuth.OAuthRegistrationIntents, {
    issue: ({ intent }, prepare) =>
      Effect.sync(() => {
        intents.set(intent.reference, intent);

        return prepare({ _tag: "RegistrationIssued", intent }, journal);
      }),
  });

  // Application provisioning: one subject per registered external identity.
  const authority = Layer.succeed(strategy.registration.RegistrationAuthority, {
    authentication: "first-confirmed-registration",
    read: (access) =>
      Effect.sync(() => {
        const intent = intents.get(access.reference);

        return intent === undefined || intent.credentialDigest !== access.credentialDigest
          ? undefined
          : { intent, application: { _tag: "Unbound" as const } };
      }),
    inspect: () =>
      Effect.succeed({ fingerprint: TokenDigest.make("registration"), eligible: true }),
    register: (input, prepare) =>
      Effect.sync(() => {
        const subjectId = SubjectId.make(`member-${input.intent.identity.subject}`);
        const credentialId = `apple-${input.intent.identity.subject}`;

        const revision = {
          subjectId,
          securityRevision: Sessions.SecurityRevision.make("1"),
          credentials: [{ credentialId, revision: Sessions.SecurityRevision.make("1") }],
        };

        credentials.set(input.intent.identity.subject, {
          requirement,
          moduleId: input.intent.context.moduleId,
          identity: input.intent.identity,
          credentialId,
          credentialRevision: Sessions.SecurityRevision.make("1"),
          revision,
        });
        intents.delete(input.intent.reference);

        return prepare(
          {
            _tag: "Registered",
            replayed: false,
            authentication: {
              intent: input.intent,
              credentialId,
              credentialRevision: Sessions.SecurityRevision.make("1"),
              revision,
            },
          },
          journal,
        );
      }),
    cleanup: () => Effect.die("unused"),
  });

  const protocol = Layer.succeed(OAuth.OAuthProtocol, {
    prepareAuthorization: () =>
      Effect.succeed({
        configuration: {
          provider,
          protocol: "oidc" as const,
          configurationGeneration: 1,
          issuer,
          responseIssuerMode: "unsupported" as const,
          callbackId: OAuth.OAuthCallbackId.make("apple"),
          redirectUri: OAuth.OAuthRedirectUri.make("https://app.test/auth/apple/callback"),
        },
        authorizationUrl: Redacted.make("https://appleid.apple.com/auth/authorize"),
        secrets: {
          namespace: "effect-auth/oauth-transaction-secrets/v1" as const,
          state: Redacted.make(state),
          oidcNonce: Redacted.make(nonce),
        },
      }),
    exchangeVerifiedIdentity: () => Effect.die("web exchange must not run"),
    prepareNative: () =>
      Effect.succeed({
        configuration: {
          provider,
          protocol: "oidc" as const,
          configurationGeneration: 1,
          issuer,
          responseIssuerMode: "unsupported" as const,
          callbackId: OAuth.OAuthNativeCallbackId,
        },
        secrets: {
          namespace: "effect-auth/oauth-transaction-secrets/v1" as const,
          state: Redacted.make(state),
          oidcNonce: Redacted.make(nonce),
        },
      }),
    // The real adapter's verification is covered in native-sign-in.test.ts.
    exchangeNativeIdentity: ({ response }) =>
      Effect.sync(() => {
        const subject = Redacted.value(response.code);

        exchanges.push(subject);

        return { identity: { provider, issuer, subject } };
      }),
  });

  const authenticationAuthority = Layer.succeed(Sessions.AuthenticationAuthority, {
    capture: () => Effect.die("unused"),
    requirements: () => Effect.succeed(requirement),
    approve: (_input, prepare) =>
      coordinateCommit((commit) => Effect.sync(() => prepare(undefined, commit))).pipe(
        Effect.map((result) => result.value),
        Effect.orDie,
        Effect.provide(LifecycleHooks.empty),
      ),
  });

  const services = yield* Layer.build(
    Layer.mergeAll(
      persistence,
      registrationIntents,
      authority,
      protocol,
      authenticationAuthority,
      Layer.succeed(strategy.SessionClaims, {
        resolve: ({ subjectId }) => Effect.succeed({ displayName: subjectId }),
      }),
      Layer.succeed(Sessions.SessionSigningKeys, keyring),
      OAuth.OAuthReturnTargets.exactRoutes(["/"]),
      OAuth.OAuthTransactionProtector.layer(keyring),
      Auth.RequestBindingConfig.layer({ generation: 1, lifetimeMillis: 300_000, keyring }),
      LifecycleHooks.empty,
    ).pipe(Layer.provideMerge(NodeCrypto.layer)),
  );

  const auth = yield* App.make.pipe(Effect.provide(services));

  /** A native client: private credentials travel beside, never inside, the payload. */
  const client = () => {
    const held = new Map<CredentialSlot, Redacted.Redacted<string>>();

    return {
      held,
      request: {
        invocation: Operations.guest,
        get credentials() {
          return Object.fromEntries(held);
        },
        credentialCommandSink: (commands: ReadonlyArray<AuthCredentialCommand>) =>
          Effect.sync(() => {
            for (const command of commands) {
              if (command._tag === "Issue") held.set(command.slot, command.credential);
              else held.delete(command.slot);
            }
          }),
      },
    };
  };

  return {
    auth,
    client,
    exchanges,
    flows,
    consumed: () => consumed,
  };
});

const run = <A, E, R>(effect: Effect.Effect<A, E, R>, request: Auth.AuthRequest["Service"]) =>
  effect.pipe(Effect.provideService(Auth.AuthRequest, request));

describe("native OAuth sign-in", () => {
  it.effect("registers a new identity, then authenticates the same subject again", () =>
    Effect.gen(function* () {
      const { auth, client, exchanges } = yield* harness();
      const device = client();

      const begun = yield* run(
        auth.nativeSignIn({ provider: "apple", returnTarget: "/" }),
        device.request,
      );

      expect(Redacted.value(begun.nonce)).toBe(nonce);
      expect(device.held.has("request-binding")).toBe(true);

      const registration = yield* run(
        auth.completeNativeSignIn({
          flowId: begun.flowId,
          provider: "apple",
          code: "apple-subject",
          user: JSON.stringify({ name: { firstName: "Ada" } }),
        }),
        device.request,
      );

      expect(registration).toMatchObject({ _tag: "RegistrationRequired", returnTarget: "/" });
      if (!("_tag" in registration) || registration._tag !== "RegistrationRequired")
        return yield* Effect.die("expected registration");

      const registered = yield* run(
        auth.register({
          reference: registration.reference,
          flowId: begun.flowId,
          commandId: "register-1",
          registration: { displayName: "Ada" },
        }),
        device.request,
      );

      expect(registered).toMatchObject({
        _tag: "Authenticated",
        session: { subjectId: "member-apple-subject" },
      });
      expect(device.held.has("session")).toBe(true);

      const returning = client();

      const again = yield* run(
        auth.nativeSignIn({ provider: "apple", returnTarget: "/" }),
        returning.request,
      );

      const signedIn = yield* run(
        auth.completeNativeSignIn({
          flowId: again.flowId,
          provider: "apple",
          code: "apple-subject",
        }),
        returning.request,
      );

      expect(signedIn).toMatchObject({
        returnTarget: "/",
        completion: { _tag: "Authenticated", session: { subjectId: "member-apple-subject" } },
      });
      expect(returning.held.has("session")).toBe(true);
      expect(returning.held.has("request-binding")).toBe(false);
      expect(exchanges).toEqual(["apple-subject", "apple-subject"]);
    }),
  );

  it.effect("requires the flow's request binding before consuming it", () =>
    Effect.gen(function* () {
      const { auth, client, exchanges, flows, consumed } = yield* harness();
      const device = client();
      const other = client();

      const begun = yield* run(
        auth.nativeSignIn({ provider: "apple", returnTarget: "/" }),
        device.request,
      );

      yield* run(auth.nativeSignIn({ provider: "apple", returnTarget: "/" }), other.request);

      const complete = (request: Auth.AuthRequest["Service"]) =>
        run(
          auth.completeNativeSignIn({
            flowId: begun.flowId,
            provider: "apple",
            code: "apple-subject",
          }),
          request,
        ).pipe(Effect.result);

      expect(yield* complete({ ...device.request, credentials: {} })).toMatchObject({
        _tag: "Failure",
        failure: { _tag: "InvalidOperationInput" },
      });
      // Another flow's valid binding does not authorize this one.
      expect(yield* complete(other.request)).toMatchObject({
        _tag: "Failure",
        failure: { _tag: "OAuthRejected" },
      });
      expect(flows.has(begun.flowId)).toBe(true);
      expect(consumed()).toBe(0);
      expect(exchanges).toEqual([]);
    }),
  );

  it.effect("keeps native and web flows on their own completions", () =>
    Effect.gen(function* () {
      const { auth, client, exchanges, consumed } = yield* harness();
      const device = client();

      const native = yield* run(
        auth.nativeSignIn({ provider: "apple", returnTarget: "/" }),
        device.request,
      );

      // The reserved native callback ID with any state never matches a native flow.
      const viaCallback = yield* run(
        auth.completeSignIn({
          flowId: native.flowId,
          provider: "apple",
          callbackId: "native",
          response: { _tag: "Code", state, code: "apple-subject" },
        }),
        device.request,
      ).pipe(Effect.result);

      expect(viaCallback).toMatchObject({ _tag: "Failure", failure: { _tag: "OAuthRejected" } });

      const browser = client();

      const web = yield* run(
        auth.signIn({ provider: "apple", returnTarget: "/" }),
        browser.request,
      );

      const viaNative = yield* run(
        auth.completeNativeSignIn({
          flowId: web.flowId,
          provider: "apple",
          code: "apple-subject",
        }),
        browser.request,
      ).pipe(Effect.result);

      expect(viaNative).toMatchObject({ _tag: "Failure", failure: { _tag: "OAuthRejected" } });
      expect(consumed()).toBe(0);
      expect(exchanges).toEqual([]);
    }),
  );
});
