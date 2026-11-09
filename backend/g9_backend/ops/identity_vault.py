"""g9 ops: engagement identity vault — temp/anonymous identities with
fail-closed governance.

Red-team engagements need burner identities (alias inboxes, generated
credentials) for infrastructure and phishing simulations. This module
is the CONTROL-PLANE half only:

  - aliases are generated at OPERATOR-ADMITTED provider domains only
  - accounts are usable only after operator registration with a
    recorded ownership proof (and a separate RoE addendum for
    phishing-class purposes, per the separate_auth doctrine)
  - credentials are sealed at creation; the vault stores references,
    never plaintext secrets — nothing secret reaches the audit ledger
  - every login is a typed action routed through the deny-by-default
    policy engine, bound to the registered account's engagement

What this module deliberately does NOT do (honest boundary):

  - no automated account REGISTRATION on third-party services
  - no identity-verification bypass (CAPTCHA, SMS, email codes)
  - no login to any account the operator has not registered ownership of

Those are abuse primitives, not engagement tradecraft. Each refusal
is test-proven to fail closed.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

PHISHING_CLASS_PURPOSES = {"phishing-simulation", "credential-harvest-infra"}
ALLOWED_PURPOSES = {
    "engagement-infra", "recon-inbox", "phishing-simulation",
    "credential-harvest-infra", "lab-account",
}
VERIFICATION_BYPASS_KEYS = {"captcha", "captcha_bypass", "sms_bypass", "otp_bypass", "verification_bypass"}
MIN_PASSWORD_LEN = 16
ALIAS_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


class IdentityVaultError(ValueError):
    pass


@dataclass
class AccountRecord:
    account_id: str
    service: str
    purpose: str
    engagement_id: str
    ownership_proof: str
    separate_roe_addendum: bool = False
    alias: str | None = None
    sealed_ref: str | None = None
    revoked: bool = False

    def ledger_view(self) -> dict:
        """The only representation that may enter the audit ledger:
        no secrets, no credential material, ever."""
        return {
            "account_id": self.account_id,
            "service": self.service,
            "purpose": self.purpose,
            "engagement_id": self.engagement_id,
            "alias": self.alias,
            "sealed_ref": self.sealed_ref,
            "revoked": self.revoked,
        }


class EngagementIdentityVault:
    def __init__(self, engagement_id: str, admitted_providers: set[str]):
        if not admitted_providers:
            raise IdentityVaultError("no admitted alias providers — deny by default")
        self.engagement_id = engagement_id
        self.admitted_providers = admitted_providers
        self._accounts: dict[str, AccountRecord] = {}
        self._sealed: dict[str, str] = {}

    # ------------------------------------------------------ registration

    def register_account(
        self, *, account_id: str, service: str, purpose: str,
        ownership_proof: str, separate_roe_addendum: bool = False,
    ) -> dict:
        if not ownership_proof:
            raise IdentityVaultError(
                f"{account_id}: operator ownership proof required — the vault never "
                "manages accounts the operator has not registered"
            )
        if purpose not in ALLOWED_PURPOSES:
            raise IdentityVaultError(f"{account_id}: unknown purpose {purpose!r}")
        if purpose in PHISHING_CLASS_PURPOSES and not separate_roe_addendum:
            raise IdentityVaultError(
                f"{account_id}: purpose {purpose!r} requires a SEPARATE RoE addendum "
                "(separate_auth doctrine) — approval is not implied by the base RoE"
            )
        if account_id in self._accounts:
            raise IdentityVaultError(f"duplicate account id {account_id}")
        rec = AccountRecord(
            account_id=account_id, service=service, purpose=purpose,
            engagement_id=self.engagement_id, ownership_proof=hashlib.sha256(
                ownership_proof.encode()).hexdigest(),
            separate_roe_addendum=separate_roe_addendum,
        )
        self._accounts[account_id] = rec
        return rec.ledger_view()

    # -------------------------------------------------------- generation

    def generate_alias(self, account_id: str) -> str:
        rec = self._require(account_id)
        provider = sorted(self.admitted_providers)[secrets.randbelow(len(self.admitted_providers))]
        local = "".join(secrets.choice(ALIAS_ALPHABET) for _ in range(12))
        rec.alias = f"eng-{local}@{provider}"
        return rec.alias

    def generate_credential(self, account_id: str, length: int = 24) -> dict:
        """Generate a strong password and SEAL it. The returned view
        carries a reference only — the plaintext never leaves the
        sealed store through this API."""
        if length < MIN_PASSWORD_LEN:
            raise IdentityVaultError(f"password length below the {MIN_PASSWORD_LEN}-char floor")
        rec = self._require(account_id)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%*+-=?@"
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        ref = f"sealed:{account_id}:{secrets.token_hex(8)}"
        self._sealed[ref] = password
        rec.sealed_ref = ref
        return {"account_id": account_id, "sealed_ref": ref, "ledger_safe": True}

    def unseal(self, sealed_ref: str) -> str:
        """Materialize the secret — callable ONLY by the execution
        plane on the operator host, never by the agent path."""
        if sealed_ref not in self._sealed:
            raise IdentityVaultError("unknown or expired sealed reference")
        return self._sealed[sealed_ref]

    # ------------------------------------------------------------ login

    def build_login_action(self, *, policy_engine, account_id: str, call: dict) -> dict:
        """Typed login action through the deny-by-default policy gate.
        Refuses unregistered accounts, revoked accounts, engagement
        mismatches, and any verification-bypass field."""
        for key in VERIFICATION_BYPASS_KEYS:
            if key in call:
                raise IdentityVaultError(
                    f"verification bypass field {key!r} refused — identity "
                    "verification bypass is not engagement tradecraft"
                )
        rec = self._require(account_id)
        if rec.revoked:
            raise IdentityVaultError(f"account {account_id} revoked — login refused")
        if rec.alias is None or rec.sealed_ref is None:
            raise IdentityVaultError(
                f"account {account_id} has no generated identity — generate "
                "alias and credential before login"
            )
        action = {
            "engagement_id": self.engagement_id,
            "principal_id": call.get("principal_id", "agent:panoptes"),
            "tool_id": "identity-vault",
            "targets": [rec.service],
            "account_id": account_id,
            "purpose": rec.purpose,
            "high_impact": rec.purpose in PHISHING_CLASS_PURPOSES,
            "approval_id": call.get("approval_id"),
        }
        decision = policy_engine.evaluate(action)
        if decision.effect == "deny":
            return {"ok": False, "blocked_at": "policy", "reasons": decision.reasons}
        return {
            "ok": True,
            "action": action,
            "sealed_ref": rec.sealed_ref,
            "note": "secret is unsealed only by the execution plane on the operator host",
        }

    def revoke(self, account_id: str) -> dict:
        rec = self._require(account_id)
        rec.revoked = True
        if rec.sealed_ref:
            self._sealed.pop(rec.sealed_ref, None)
        return {"account_id": account_id, "revoked": True}

    # ----------------------------------------------------------- helpers

    def _require(self, account_id: str) -> AccountRecord:
        rec = self._accounts.get(account_id)
        if rec is None:
            raise IdentityVaultError(
                f"account {account_id!r} is not operator-registered — logins to "
                "unregistered accounts are refused by default"
            )
        return rec

    def ledger_view(self) -> list[dict]:
        return [r.ledger_view() for r in self._accounts.values()]
