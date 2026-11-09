import { generateKeyPairSync } from "node:crypto";

import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import { it } from "@effect/vitest";
import * as Apple from "@yielded/auth/Apple";
import {
  OAuthCallbackId,
  OAuthProviderKey,
  OAuthRedirectUri,
  type OAuthProtocol,
  type OAuthNativeProtocolPreparation,
} from "@yielded/auth/OAuth";
import { RequestBindingFlowId } from "@yielded/auth/Operations";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as Jwk from "effect/jose/Jwk";
import * as Jwt from "effect/jose/Jwt";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as TestClock from "effect/testing/TestClock";
import { describe, expect } from "vite-plus/test";

import { expectTag } from "./helpers/oauth";

// Human-requested seam: native (no-browser) Sign in with Apple through the real Apple
// provider, its discovery pinning, client-secret JWT and shared ID-token verifier. Only
// Apple's HTTP endpoints are substituted.
// Failure inventory:
// 1. A native code is redeemed by the bundle-ID client without redirect_uri, and the
//    redeemed ID token's nonce must equal the flow nonce.
// 2. A redeemed ID token without nonce is accepted only with a platform ID token that
//    carries the nonce and the same subject; neither nonce present is rejected.
// 3. A platform ID token for another subject is rejected.
// 4. Web and native registrations coexist, and neither serves the other flow.
// 5. Apple's first-consent `user` JSON fills the native profile name.

const seconds = 1_700_000_000;
const platform = Layer.mergeAll(FetchHttpClient.layer, NodeCrypto.layer);
const json = (body: unknown) => Response.json(body);
const apple = OAuthProviderKey.make("apple");
const bundleId = "com.example.app";
const servicesId = "com.example.services";

const IdToken = Schema.Struct({
  iss: Schema.String,
  sub: Schema.String,
  aud: Schema.String,
  iat: Schema.Finite,
  exp: Schema.Finite,
  nonce: Schema.optionalKey(Schema.String),
  email: Schema.String,
});

const signingKey = () =>
  Redacted.make(
    generateKeyPairSync("ec", { namedCurve: "P-256" })
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString(),
  );

const registration = (kind: "web" | "native", clientId: string) => ({
  kind,
  clientId,
  teamId: "TEAM123456",
  keyId: "KEY1234567",
  privateKey: signingKey(),
  scopes: ["openid", "email", "name"] as const,
});

interface TokenRequest {
  readonly clientId: string | null;
  readonly redirectUri: string | null;
}

const harness = Effect.fnUntraced(function* (
  kinds: ReadonlyArray<"web" | "native"> = ["web", "native"],
) {
  yield* TestClock.setTime(seconds * 1000);
  const pair = yield* Jwk.generateKeyPair({ algorithm: "RS256", kid: "apple" });
  const signing = yield* Jwk.importPrivate(pair.privateKey, "RS256");
  const requests: Array<TokenRequest> = [];
  let tokenEndpointIdToken = "";

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);

    if (url === "https://appleid.apple.com/.well-known/openid-configuration")
      return json({
        issuer: "https://appleid.apple.com",
        authorization_endpoint: "https://appleid.apple.com/auth/authorize",
        token_endpoint: "https://appleid.apple.com/auth/token",
        jwks_uri: "https://appleid.apple.com/auth/keys",
        response_types_supported: ["code"],
        response_modes_supported: ["query", "fragment", "form_post"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
      });
    if (url === "https://appleid.apple.com/auth/keys") return json({ keys: [pair.publicKey] });
    if (url === "https://appleid.apple.com/auth/token") {
      const form =
        init?.body instanceof URLSearchParams
          ? init.body
          : new URLSearchParams(
              typeof init?.body === "string"
                ? init.body
                : init?.body instanceof Uint8Array
                  ? new TextDecoder().decode(init.body)
                  : "",
            );

      requests.push({ clientId: form.get("client_id"), redirectUri: form.get("redirect_uri") });

      return json({
        access_token: "private-access",
        token_type: "Bearer",
        refresh_token: "private-refresh",
        id_token: tokenEndpointIdToken,
      });
    }
    throw new Error(`Unexpected endpoint ${url}`);
  };

  const protocol = yield* Apple.provider({
    registrations: kinds.map((kind) =>
      registration(kind, kind === "native" ? bundleId : servicesId),
    ),
  })
    .configure({
      provider: apple,
      callbacks: [
        {
          callbackId: OAuthCallbackId.make("apple"),
          redirectUri: OAuthRedirectUri.make("https://app.test/auth/apple/callback"),
        },
      ],
    })
    .pipe(Effect.provideService(FetchHttpClient.Fetch, fetch));

  const sign = (claims: {
    readonly sub?: string;
    readonly nonce?: string;
    readonly aud?: string;
  }) =>
    Jwt.sign(
      IdToken,
      {
        iss: "https://appleid.apple.com",
        sub: claims.sub ?? "apple-subject",
        aud: claims.aud ?? bundleId,
        iat: seconds,
        exp: seconds + 300,
        ...(claims.nonce === undefined ? {} : { nonce: claims.nonce }),
        email: "ada@privaterelay.appleid.com",
      },
      signing,
      { kid: "apple" },
    ).pipe(Effect.map(Redacted.value));

  return {
    protocol,
    requests,
    sign,
    redeemedIdToken: (token: string) => {
      tokenEndpointIdToken = token;
    },
  };
});

const exchange = (
  protocol: OAuthProtocol["Service"],
  started: OAuthNativeProtocolPreparation,
  response: { readonly idToken?: string; readonly user?: string } = {},
) => {
  if (protocol.exchangeNativeIdentity === undefined) return Effect.die("missing native exchange");

  return protocol.exchangeNativeIdentity({
    configuration: started.configuration,
    secrets: started.secrets,
    verificationStartedAt: DateTime.makeUnsafe(seconds * 1000),
    response: {
      code: Redacted.make("platform-code"),
      ...(response.idToken === undefined ? {} : { idToken: Redacted.make(response.idToken) }),
      ...(response.user === undefined ? {} : { user: response.user }),
    },
  });
};

const prepare = (protocol: OAuthProtocol["Service"], flowId: string) =>
  protocol.prepareNative === undefined
    ? Effect.die("missing native preparation")
    : protocol.prepareNative({ provider: apple, flowId: RequestBindingFlowId.make(flowId) });

const nonceOf = (started: OAuthNativeProtocolPreparation) => {
  const nonce = started.secrets.oidcNonce;

  if (nonce === undefined) throw new Error("expected a native nonce");

  return Redacted.value(nonce);
};

describe("native Sign in with Apple exchange", () => {
  it.effect("redeems with the bundle ID, no redirect_uri, and the flow nonce", () =>
    Effect.gen(function* () {
      const { protocol, requests, sign, redeemedIdToken } = yield* harness();
      const started = yield* prepare(protocol, "flow-native");

      expect(started.configuration).toMatchObject({ callbackId: "native", protocol: "oidc" });
      expect(started.configuration).not.toHaveProperty("redirectUri");
      expect(started.secrets.pkceVerifier).toBeUndefined();

      redeemedIdToken(yield* sign({ nonce: nonceOf(started) }));

      const verified = yield* exchange(protocol, started, {
        user: JSON.stringify({ name: { firstName: "Ada", lastName: "Lovelace" } }),
      });

      expect(verified.identity).toEqual({
        provider: "apple",
        issuer: "https://appleid.apple.com",
        subject: "apple-subject",
      });
      expect(verified.profile?.displayName).toBe("Ada Lovelace");
      expect(requests).toEqual([{ clientId: bundleId, redirectUri: null }]);
    }).pipe(Effect.provide(platform), Effect.scoped),
  );

  it.effect("rejects a redeemed ID token for another nonce", () =>
    Effect.gen(function* () {
      const { protocol, sign, redeemedIdToken } = yield* harness();
      const started = yield* prepare(protocol, "flow-mismatch");

      redeemedIdToken(yield* sign({ nonce: "B".repeat(43) }));
      yield* expectTag(exchange(protocol, started), "OAuthProtocolRejected");
    }).pipe(Effect.provide(platform), Effect.scoped),
  );

  it.effect("accepts a nonce-less redeemed token only with a matching platform token", () =>
    Effect.gen(function* () {
      const { protocol, sign, redeemedIdToken } = yield* harness();
      const started = yield* prepare(protocol, "flow-corroborated");
      const nonce = nonceOf(started);

      redeemedIdToken(yield* sign({}));
      // Neither token carries the nonce.
      yield* expectTag(exchange(protocol, started), "OAuthProtocolRejected");
      yield* expectTag(
        exchange(protocol, started, { idToken: yield* sign({}) }),
        "OAuthProtocolRejected",
      );
      // The platform token proves the nonce, but for another subject.
      yield* expectTag(
        exchange(protocol, started, { idToken: yield* sign({ nonce, sub: "other-subject" }) }),
        "OAuthProtocolRejected",
      );
      // A platform token for another client never corroborates.
      yield* expectTag(
        exchange(protocol, started, { idToken: yield* sign({ nonce, aud: servicesId }) }),
        "OAuthProtocolRejected",
      );

      const verified = yield* exchange(protocol, started, { idToken: yield* sign({ nonce }) });

      expect(verified.identity.subject).toBe("apple-subject");
    }).pipe(Effect.provide(platform), Effect.scoped),
  );

  it.effect("rejects a platform token for another subject even when the nonce matches", () =>
    Effect.gen(function* () {
      const { protocol, sign, redeemedIdToken } = yield* harness();
      const started = yield* prepare(protocol, "flow-other-subject");
      const nonce = nonceOf(started);

      redeemedIdToken(yield* sign({ nonce }));
      yield* expectTag(
        exchange(protocol, started, { idToken: yield* sign({ nonce, sub: "other-subject" }) }),
        "OAuthProtocolRejected",
      );
    }).pipe(Effect.provide(platform), Effect.scoped),
  );

  it.effect("keeps web and native registrations separate", () =>
    Effect.gen(function* () {
      const both = yield* harness();

      const web = yield* both.protocol.prepareAuthorization({
        provider: apple,
        flowId: RequestBindingFlowId.make("flow-web"),
      });

      expect(Redacted.value(web.authorizationUrl)).toContain(`client_id=${servicesId}`);
      expect(web.configuration.redirectUri).toBe("https://app.test/auth/apple/callback");

      const webOnly = yield* harness(["web"]);

      yield* expectTag(prepare(webOnly.protocol, "flow-web-only"), "OAuthRejected");

      const nativeOnly = yield* harness(["native"]);

      yield* expectTag(
        nativeOnly.protocol.prepareAuthorization({
          provider: apple,
          flowId: RequestBindingFlowId.make("flow-native-only"),
        }),
        "OAuthRejected",
      );
      // A native flow cannot be redeemed through the web exchange.
      const started = yield* prepare(nativeOnly.protocol, "flow-native-as-web");

      yield* expectTag(
        nativeOnly.protocol.exchangeVerifiedIdentity({
          configuration: {
            ...started.configuration,
            redirectUri: OAuthRedirectUri.make("https://app.test/auth/apple/callback"),
          },
          secrets: started.secrets,
          verificationStartedAt: DateTime.makeUnsafe(seconds * 1000),
          response: {
            _tag: "Code",
            state: started.secrets.state,
            code: Redacted.make("platform-code"),
          },
        }),
        "OAuthUnavailable",
      );
      expect(nativeOnly.requests).toEqual([]);
    }).pipe(Effect.provide(platform), Effect.scoped),
  );
});
