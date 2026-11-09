---
"@yielded/auth": minor
"@yielded/oauth": minor
---

Add native OIDC sign-in for platform sheets such as Sign in with Apple on iOS: declare an Apple `kind: "native"` registration with the bundle ID and expose `AuthContract.oauthNativeSignIn` and `AuthContract.oauthCompleteNativeSignIn`. Add `issueAuthorizationCode` to OpenID servers for pre-approved first-party apps, allow `codeGrant` without a redirect URI, and add the `nonceSubject` ID-token verification option.
