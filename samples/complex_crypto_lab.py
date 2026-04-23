"""
Complex cryptography scenario file for analyzer benchmarking.

Goal:
- Provide a long, layered code sample where static pattern matching sees only part
  of the picture while LLM can infer intent from context.
- Mix legacy and modern primitives in config-driven and wrapper-heavy style.

This file is intentionally verbose and architecture-heavy for testing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# -----------------------------------------------------------------------------
# Data contracts
# -----------------------------------------------------------------------------


@dataclass
class CryptoPolicy:
    name: str
    profile: str
    preferred_cipher: str
    fallback_cipher: str
    digest_primary: str
    digest_secondary: str
    sign_algorithm: str
    key_size_bits: int
    iv_size_bits: int
    enable_legacy_mode: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Envelope:
    tenant_id: str
    message_id: str
    created_at: str
    payload_b64: str
    digest_hex: str
    signature_b64: str
    cipher_name: str
    digest_name: str
    sign_name: str
    key_size_bits: int
    mode: str
    headers: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KeyRecord:
    key_id: str
    purpose: str
    algorithm: str
    length_bits: int
    created_at: str
    material_hex: str


# -----------------------------------------------------------------------------
# Registry and policy builders
# -----------------------------------------------------------------------------


def build_default_policies() -> Dict[str, CryptoPolicy]:
    """Construct rich policy set with explicit and implicit crypto hints."""
    return {
        "legacy-enterprise": CryptoPolicy(
            name="legacy-enterprise",
            profile="compatibility",
            preferred_cipher="AES-256-CBC",
            fallback_cipher="AES-128-CBC",
            digest_primary="sha1",
            digest_secondary="md5",
            sign_algorithm="RSA-2048",
            key_size_bits=256,
            iv_size_bits=128,
            enable_legacy_mode=True,
            metadata={
                "notes": "Old partner systems require CBC and RSA-2048 signatures",
                "deprecated": True,
                "rotation_days": 365,
            },
        ),
        "balanced": CryptoPolicy(
            name="balanced",
            profile="mixed",
            preferred_cipher="AES-256-GCM",
            fallback_cipher="ChaCha20-Poly1305",
            digest_primary="sha256",
            digest_secondary="sha512",
            sign_algorithm="ECDSA-P256",
            key_size_bits=256,
            iv_size_bits=96,
            metadata={
                "notes": "Balanced profile for web APIs",
                "rotation_days": 180,
            },
        ),
        "pqc-pilot": CryptoPolicy(
            name="pqc-pilot",
            profile="future",
            preferred_cipher="AES-256-GCM",
            fallback_cipher="AES-256-CTR",
            digest_primary="sha512",
            digest_secondary="sha3_256",
            sign_algorithm="ML-DSA",
            key_size_bits=256,
            iv_size_bits=96,
            metadata={
                "kem": "ML-KEM",
                "legacy_bridge": "RSA-3072",
                "notes": "Pilot profile with PQC naming references",
            },
        ),
    }


# -----------------------------------------------------------------------------
# Key vault with layered derivation and labels
# -----------------------------------------------------------------------------


class KeyVault:
    def __init__(self, tenant_seed: Optional[str] = None) -> None:
        self.tenant_seed = tenant_seed or secrets.token_hex(16)
        self._records: Dict[str, KeyRecord] = {}

    def _derive_material(self, label: str, bits: int, digest_name: str) -> bytes:
        # Config-driven hashing style to stress contextual interpretation.
        algo = getattr(hashlib, digest_name)
        digest = algo()
        digest.update(self.tenant_seed.encode("utf-8"))
        digest.update(label.encode("utf-8"))
        out = digest.digest()

        target_size = bits // 8
        while len(out) < target_size:
            digest = algo()
            digest.update(out)
            out += digest.digest()
        return out[:target_size]

    def issue_key(self, purpose: str, algorithm: str, bits: int, digest_name: str = "sha256") -> KeyRecord:
        now = datetime.utcnow().isoformat()
        key_id = f"k-{purpose}-{secrets.token_hex(6)}"
        label = f"{purpose}:{algorithm}:{bits}:{now}"
        material = self._derive_material(label, bits, digest_name)

        rec = KeyRecord(
            key_id=key_id,
            purpose=purpose,
            algorithm=algorithm,
            length_bits=bits,
            created_at=now,
            material_hex=material.hex(),
        )
        self._records[key_id] = rec
        return rec

    def get(self, key_id: str) -> KeyRecord:
        return self._records[key_id]


# -----------------------------------------------------------------------------
# Hashing and signing wrappers
# -----------------------------------------------------------------------------


class DigestEngine:
    def __init__(self, primary: str, secondary: str) -> None:
        self.primary = primary
        self.secondary = secondary

    def digest(self, payload: bytes, strong: bool = True) -> str:
        selected = self.primary if strong else self.secondary

        if selected in {"sha3_256", "sha3-256"}:
            d = hashlib.sha3_256()
            d.update(payload)
            return d.hexdigest()

        fn = getattr(hashlib, selected)
        d = fn()
        d.update(payload)
        return d.hexdigest()

    def mac(self, payload: bytes, key_material: bytes, digest_name: Optional[str] = None) -> str:
        use_digest = digest_name or self.primary
        return hmac.new(key_material, payload, getattr(hashlib, use_digest)).hexdigest()


class SignatureFacade:
    """
    Pseudo signature layer.

    Intentionally references RSA/ECDSA/ML-DSA terminology in indirect code paths.
    """

    def __init__(self, sign_algorithm: str) -> None:
        self.sign_algorithm = sign_algorithm

    def sign(self, payload: bytes, key_material: bytes) -> bytes:
        # This is not real asymmetric crypto; it is test scaffolding.
        # We use HMAC internally but name paths by sign_algorithm to test analyzer context.
        algo_hint = self.sign_algorithm.lower()

        if "rsa" in algo_hint:
            digest_name = "sha256"
        elif "ecdsa" in algo_hint:
            digest_name = "sha512"
        elif "ml-dsa" in algo_hint:
            digest_name = "sha3_256"
        else:
            digest_name = "sha256"

        raw = hmac.new(key_material, payload, getattr(hashlib, digest_name)).digest()
        return raw

    def verify(self, payload: bytes, signature: bytes, key_material: bytes) -> bool:
        expected = self.sign(payload, key_material)
        return hmac.compare_digest(expected, signature)


# -----------------------------------------------------------------------------
# Cipher abstraction (semantic only)
# -----------------------------------------------------------------------------


class CipherFacade:
    """
    Semantic cipher simulation.

    Notes for analyzer context:
    - Modes referenced: CBC, GCM, CTR
    - Key references: AES-128, AES-256
    - PQC bridge references: ML-KEM labels in policy metadata
    """

    def __init__(self, cipher_name: str, iv_size_bits: int) -> None:
        self.cipher_name = cipher_name
        self.iv_size_bits = iv_size_bits

    def _xor_stream(self, data: bytes, key_material: bytes, nonce: bytes) -> bytes:
        seed = hashlib.sha256(key_material + nonce).digest()
        out = bytearray()
        for i, b in enumerate(data):
            out.append(b ^ seed[i % len(seed)])
        return bytes(out)

    def encrypt(self, plaintext: bytes, key_material: bytes) -> Tuple[bytes, bytes, str]:
        mode = "UNKNOWN"
        upper_name = self.cipher_name.upper()

        if "GCM" in upper_name:
            mode = "GCM"
        elif "CBC" in upper_name:
            mode = "CBC"
        elif "CTR" in upper_name:
            mode = "CTR"

        nonce = secrets.token_bytes(self.iv_size_bits // 8)
        ciphertext = self._xor_stream(plaintext, key_material, nonce)
        return nonce, ciphertext, mode

    def decrypt(self, nonce: bytes, ciphertext: bytes, key_material: bytes) -> bytes:
        return self._xor_stream(ciphertext, key_material, nonce)


# -----------------------------------------------------------------------------
# Orchestrator
# -----------------------------------------------------------------------------


class CryptoOrchestrator:
    def __init__(self, tenant_id: str, policy: CryptoPolicy) -> None:
        self.tenant_id = tenant_id
        self.policy = policy
        self.vault = KeyVault(tenant_seed=f"tenant:{tenant_id}")
        self.digest_engine = DigestEngine(policy.digest_primary, policy.digest_secondary)
        self.signature = SignatureFacade(policy.sign_algorithm)
        self.cipher = CipherFacade(policy.preferred_cipher, policy.iv_size_bits)

    def _choose_digest_strength(self, payload: bytes) -> bool:
        # Strong digest for medium+ payload and future profile.
        if self.policy.profile == "future":
            return True
        return len(payload) > 256

    def _header_block(self, key_rec: KeyRecord, mode: str) -> Dict[str, Any]:
        return {
            "tenant": self.tenant_id,
            "profile": self.policy.profile,
            "cipher": self.policy.preferred_cipher,
            "fallback": self.policy.fallback_cipher,
            "digest_primary": self.policy.digest_primary,
            "digest_secondary": self.policy.digest_secondary,
            "sign_algorithm": self.policy.sign_algorithm,
            "key_id": key_rec.key_id,
            "key_bits": key_rec.length_bits,
            "mode": mode,
            "legacy_mode": self.policy.enable_legacy_mode,
            "created_at": datetime.utcnow().isoformat(),
            "pqc_kem_hint": self.policy.metadata.get("kem", "none"),
        }

    def seal(self, message_id: str, payload: Dict[str, Any]) -> Envelope:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")

        key_rec = self.vault.issue_key(
            purpose="encryption",
            algorithm=self.policy.preferred_cipher,
            bits=self.policy.key_size_bits,
            digest_name=self.policy.digest_primary,
        )

        key_bytes = bytes.fromhex(key_rec.material_hex)
        nonce, ciphertext, mode = self.cipher.encrypt(raw, key_bytes)

        strong = self._choose_digest_strength(raw)
        digest_hex = self.digest_engine.digest(raw, strong=strong)

        sign_rec = self.vault.issue_key(
            purpose="signing",
            algorithm=self.policy.sign_algorithm,
            bits=256,
            digest_name=self.policy.digest_secondary,
        )
        sign_key = bytes.fromhex(sign_rec.material_hex)
        signature = self.signature.sign(ciphertext + nonce, sign_key)

        envelope = Envelope(
            tenant_id=self.tenant_id,
            message_id=message_id,
            created_at=datetime.utcnow().isoformat(),
            payload_b64=base64.b64encode(nonce + ciphertext).decode("ascii"),
            digest_hex=digest_hex,
            signature_b64=base64.b64encode(signature).decode("ascii"),
            cipher_name=self.policy.preferred_cipher,
            digest_name=self.policy.digest_primary if strong else self.policy.digest_secondary,
            sign_name=self.policy.sign_algorithm,
            key_size_bits=self.policy.key_size_bits,
            mode=mode,
            headers=self._header_block(key_rec, mode),
        )
        return envelope

    def open(self, envelope: Envelope) -> Dict[str, Any]:
        blob = base64.b64decode(envelope.payload_b64.encode("ascii"))
        nonce_size = self.policy.iv_size_bits // 8
        nonce = blob[:nonce_size]
        ciphertext = blob[nonce_size:]

        # For demo only: issue deterministic key again.
        # In real systems key lookup by key_id should be used.
        key_rec = self.vault.issue_key(
            purpose="encryption",
            algorithm=self.policy.preferred_cipher,
            bits=self.policy.key_size_bits,
            digest_name=self.policy.digest_primary,
        )
        key_bytes = bytes.fromhex(key_rec.material_hex)

        plaintext = self.cipher.decrypt(nonce, ciphertext, key_bytes)
        return json.loads(plaintext.decode("utf-8"))


# -----------------------------------------------------------------------------
# Scenario runner
# -----------------------------------------------------------------------------


def run_profile(profile_name: str) -> Dict[str, Any]:
    policies = build_default_policies()
    if profile_name not in policies:
        raise ValueError(f"Unknown profile: {profile_name}")

    orchestrator = CryptoOrchestrator(
        tenant_id="tenant-blue",
        policy=policies[profile_name],
    )

    sample_payload = {
        "transaction_id": secrets.token_hex(8),
        "amount": 1442.73,
        "currency": "TRY",
        "customer": {
            "id": "C-100992",
            "segment": "enterprise",
        },
        "flags": ["priority", "cross-region", "audit"],
        "timestamp": datetime.utcnow().isoformat(),
        "notes": "Route over secure channel, keep detached signature",
    }

    envelope = orchestrator.seal(message_id="msg-001", payload=sample_payload)

    return {
        "profile": profile_name,
        "cipher": envelope.cipher_name,
        "digest": envelope.digest_name,
        "sign": envelope.sign_name,
        "mode": envelope.mode,
        "key_size_bits": envelope.key_size_bits,
        "header": envelope.headers,
        "payload_preview": envelope.payload_b64[:48] + "...",
    }


def compare_profiles() -> List[Dict[str, Any]]:
    outputs = []
    for name in ["legacy-enterprise", "balanced", "pqc-pilot"]:
        outputs.append(run_profile(name))
    return outputs


if __name__ == "__main__":
    print("Running complex cryptography scenario...")
    rows = compare_profiles()
    for row in rows:
        print("-" * 60)
        print(json.dumps(row, indent=2))
