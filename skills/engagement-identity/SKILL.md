---
name: engagement-identity
description: "Engagement identity management for authorized red-team work: temp/anonymous alias generation at operator-admitted provider domains, sealed credential generation, and gated login actions for operator-registered accounts. Load before creating engagement identities or automating logins."
allowed-tools: Read Write
metadata:
  subdomain: ops
  when_to_use: "burner identity, alias inbox, temp email, anonymous email, credential generation, sealed credentials, engagement account login, phishing simulation infrastructure, identity vault"
  tags: opsec, identity, credentials, engagement-infra, governance
  upstream_ref: "G9 separate_auth doctrine + operator anonymity rule (opsec-stealth-cleanup), adapted for the engagement identity vault"
---

# Engagement Identity — Temp/Anonymous Identities, Sealed Credentials, Gated Logins

The identity vault (`backend/g9_backend/ops/identity_vault.py`) owns this
skill. It is the control-plane half of engagement identity management:
aliases and credentials are **generated and governed here**; actual
mailbox access and logins execute on the operator's G9 host.

## What this skill does

1. **Alias generation** — `eng-<random12>@<admitted-provider>`. Provider
   domains are operator-admitted at vault construction (self-hosted
   SimpleLogin/AnonAddy instances or operator-owned domains). No
   third-party temp-mail service is used: those services are not
   admission-qualified, leak engagement context, and their inboxes are
   not under operator control.
2. **Credential generation** — `secrets`-based, 16-char floor, sealed at
   creation. The vault stores a **reference only**; plaintext is
   materialized solely by the execution plane via `unseal()`. No secret
   ever reaches the audit ledger, a tool argument, or a log line.
3. **Gated login actions** — every login is a typed action through the
   deny-by-default policy engine: registered account, matching
   engagement, signed RoE, and for phishing-class purposes a recorded
   **separate RoE addendum** (`separate_auth` doctrine — phishing is
   never implied by the base RoE).

## Operating rules (non-negotiable)

1. **Operator-registered accounts only.** Login to any account without a
   recorded ownership proof is refused — the vault never manages
   accounts the operator has not registered, and agents cannot register
   accounts into the vault themselves.
2. **No automated registration on third-party services.** The vault
   does not create accounts on platforms. Account creation on target or
   third-party platforms is out of scope; where an engagement needs a
   platform account, the operator creates it and registers it here.
3. **No identity-verification bypass.** CAPTCHA, SMS, and OTP bypass
   fields are refused at the contract boundary and in the login action
   builder. Those are abuse primitives, not engagement tradecraft.
4. **Purpose is declared at registration** and must be in the allowlist
   (`engagement-infra`, `recon-inbox`, `phishing-simulation`,
   `credential-harvest-infra`, `lab-account`). Phishing-class purposes
   require the separate RoE addendum before the account can even be
   registered.
5. **Operator anonymity.** Aliases carry no personal identifiers
   (rule 4 of opsec-stealth-cleanup). The alias local part is random.
6. **Revocation destroys the secret.** `revoke()` removes the sealed
   credential immediately; a revoked account fails closed on login.

## Honest boundary

This skill governs identities; it does not execute logins. The
execution plane (host-side Stage 02) unseals credentials and performs
the session. Until that stage lands, `build_login_action()` returns a
policy-cleared typed action — the same pattern as every other adapter:
the command is the contract, the host executes it.
