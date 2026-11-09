import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import * as SqliteClient from "@effect/sql-sqlite-node/SqliteClient";
import { it } from "@effect/vitest";
import { OAuthScope, OAuthServer } from "@yielded/auth";
import { SubjectId } from "@yielded/auth/Schema";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as Jwk from "effect/jose/Jwk";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as SqlClient from "effect/sql/SqlClient";
import { describe, expect } from "vite-plus/test";

import { OAuthServerPersistence } from "../src/internal/oauth-server";

// Human-requested seam: programmatic authorization-code issuance for an application
// that authenticated natively, redeemed at the unchanged token endpoint over SQLite.
// Failure inventory:
// 1. An approved first-party client receives a code that the token endpoint redeems
//    once, with PKCE, its exact redirect and the ID-token nonce.
// 2. Wrong redirect, missing PKCE, unknown or disabled clients, missing openid, an
//    inactive session and an unapproved client are rejected without a code.

const server = OAuthServer.makeOpenId("app");
const origin = "https://app.example.com";
const redirectUri = `${origin}/native/callback`;
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const client = (clientId: string, extra: Partial<OAuthServer.Client> = {}) => ({
  clientId,
  name: clientId,
  redirectUris: [redirectUri] as const,
  applicationType: "native" as const,
  ...extra,
});

const authentication = OAuthServer.Authentication.make({
  subjectId: SubjectId.make("member"),
  sessionId: "session",
  securityRevision: "1",
  authenticatedAtMillis: 0,
  expiresAtMillis: 3_600_000,
});

const harness = Effect.fnUntraced(function* () {
  const pair = yield* Jwk.generateKeyPair({ algorithm: "RS256", kid: "id" });

  const database = Layer.effectDiscard(
    Effect.gen(function* () {
      for (const migration of OAuthServerPersistence.migrations)
        yield* (yield* SqlClient.SqlClient).unsafe(migration);
    }),
  ).pipe(Layer.provideMerge(SqliteClient.layer({ filename: ":memory:" })));

  const identity = Layer.succeed(server.Identity, {
    current: Effect.as(Effect.void, undefined),
    active: (value) => Effect.succeed(value.sessionId === "session"),
    profile: () => Effect.succeed({ name: "Member" }),
  });

  // Application policy: only the first-party app is pre-approved.
  const consent = Layer.succeed(OAuthServer.OpenIdConsent, {
    approved: (input) => Effect.succeed(input.clientId === "first-party"),
  });

  return yield* Layer.build(
    server
      .layer({
        origin,
        loginPath: "/login",
        clients: [
          client("first-party"),
          client("third-party"),
          client("disabled", { grantTypes: ["refresh_token"] }),
        ],
        keys: {
          activeKeyId: "v1",
          keys: [
            { id: "v1", material: Redacted.make(Base64Url.encode(new Uint8Array(32).fill(9))) },
          ],
        },
        identityKeys: {
          activeKeyId: "id",
          privateKey: pair.privateKey,
          publicKeys: [pair.publicKey],
        },
      })
      .pipe(
        Layer.provide([identity, consent, FetchHttpClient.layer]),
        Layer.provideMerge(OAuthServerPersistence.layer.pipe(Layer.provideMerge(database))),
      ),
  );
});

const request = {
  clientId: "first-party",
  redirectUri,
  scopes: [OAuthScope.make("openid"), OAuthScope.make("profile")],
  state: "client-state",
  codeChallenge: challenge,
  codeChallengeMethod: "S256",
  nonce: "client-nonce",
  authentication,
} satisfies OAuthServer.AuthorizationCodeRequest;

const exchange = (code: string) =>
  new Request(`${origin}${server.paths.token}`, {
    method: "POST",
    headers: { origin },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: "first-party",
      redirect_uri: redirectUri,
      code,
      code_verifier: verifier,
    }),
  });

const Tokens = Schema.Struct({ access_token: Schema.String, id_token: Schema.String });

const IdClaims = Schema.Struct({ sub: Schema.String, aud: Schema.String, nonce: Schema.String });

const claimsOf = (token: string) =>
  Schema.decodeSync(Schema.fromJsonString(IdClaims))(
    new TextDecoder().decode(Result.getOrThrow(Base64Url.decode(token.split(".")[1] ?? ""))),
  );

describe("OpenID programmatic authorization codes", () => {
  it.effect("issues a code the token endpoint redeems once", () =>
    Effect.gen(function* () {
      const context = yield* harness();
      const service = yield* server.Service.pipe(Effect.provide(context));
      const issued = yield* service.issueAuthorizationCode(request);

      expect(issued).toMatchObject({ state: "client-state", iss: origin });

      const response = yield* service.handle(exchange(Redacted.value(issued.code)));

      expect(response.status).toBe(200);

      const tokens = yield* Effect.promise(() => response.json()).pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(Tokens)),
      );

      expect(claimsOf(tokens.id_token)).toMatchObject({
        sub: "member",
        aud: "first-party",
        nonce: "client-nonce",
      });
      expect((yield* service.verify(Redacted.make(tokens.access_token))).subjectId).toBe("member");

      const replay = yield* service.handle(exchange(Redacted.value(issued.code)));

      expect(replay.status).toBe(400);
      expect(yield* Effect.promise(() => replay.json())).toEqual({ error: "invalid_grant" });
    }).pipe(Effect.provide(NodeCrypto.layer)),
  );

  it.effect("applies the authorization endpoint's client and consent rules", () =>
    Effect.gen(function* () {
      const context = yield* harness();
      const service = yield* server.Service.pipe(Effect.provide(context));

      const rejected = (input: Parameters<typeof service.issueAuthorizationCode>[0]) =>
        service.issueAuthorizationCode(input).pipe(
          Effect.flip,
          Effect.map((error) => (error._tag === "OAuthServerRejected" ? error.error : error._tag)),
        );

      expect(yield* rejected({ ...request, redirectUri: `${origin}/other` })).toBe(
        "invalid_request",
      );
      expect(yield* rejected({ ...request, codeChallenge: "" })).toBe("invalid_request");
      expect(yield* rejected({ ...request, clientId: "unknown" })).toBe("invalid_client");
      expect(yield* rejected({ ...request, clientId: "disabled" })).toBe("unauthorized_client");
      expect(yield* rejected({ ...request, scopes: [OAuthScope.make("profile")] })).toBe(
        "invalid_scope",
      );
      expect(
        yield* rejected({
          ...request,
          authentication: { ...authentication, sessionId: "revoked" },
        }),
      ).toBe("login_required");
      // Never auto-consent: a client without prior approval stays interactive.
      expect(yield* rejected({ ...request, clientId: "third-party" })).toBe("consent_required");
    }).pipe(Effect.provide(NodeCrypto.layer)),
  );
});
