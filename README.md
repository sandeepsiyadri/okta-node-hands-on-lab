# Okta Node.js Hands-on Lab

This lab teaches IAM, SSO, OIDC, and RBAC using Okta + a local Node.js Express app.

## What you will learn

- Okta-hosted login
- OIDC Authorization Code flow with PKCE
- Local session creation
- ID token claims
- Group-based RBAC
- SSO behavior when using multiple apps

## Prerequisites

- Node.js 18+
- Okta Integrator Free Plan / Developer org

## Okta Configuration

Create an OIDC Web Application in Okta.

Use these values:

- Sign-in redirect URI: `http://localhost:3000/authorization-code/callback`
- Sign-out redirect URI: `http://localhost:3000`
- Grant type: Authorization Code
- Client authentication: Client Secret

Create Okta groups:

- `Admin`
- `User`

Assign your test user to either group.

Add a groups claim in your authorization server so the app receives group membership in the ID token.

## Run locally

```bash
npm install
cp .env.example .env
# update .env with Okta values
npm start
```

Open:

```text
http://localhost:3000
```

## Test RBAC

- User in `Admin` group can open `/admin`
- User not in `Admin` group receives 403

## Optional SSO test

Copy the same folder to another directory and run it on port 3001.
Create another Okta OIDC app with callback:

```text
http://localhost:3001/authorization-code/callback
```

Login to App 1, then open App 2. Okta should not ask for credentials again if the Okta browser session is still active.
