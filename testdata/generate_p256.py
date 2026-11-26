#!/usr/bin/env python3
"""Create a vouchkit P-256 test vector with OpenSSL and the independently framed payload."""

import json
from pathlib import Path
import tempfile

from generate import CRATE, NOW, ROOT, license_payload, run, short

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SEED = bytes([68]) * 32
KEY_ID = 254


def read_der_signature(data):
    if len(data) < 6 or data[0] != 0x30 or data[1] != len(data) - 2:
        raise ValueError("unexpected signature DER framing")
    values = []
    rest = data[2:]
    for _ in range(2):
        if len(rest) < 3 or rest[0] != 2 or rest[1] == 0:
            raise ValueError("unexpected signature DER integer")
        size = rest[1]
        values.append(int.from_bytes(rest[2 : 2 + size], "big"))
        rest = rest[2 + size :]
    if rest or not all(0 < value < N for value in values):
        raise ValueError("invalid signature scalars")
    return values


def main():
    # SEC1 ECPrivateKey with the secp256r1 named-curve parameters.
    key = bytes.fromhex("30310201010420") + SEED + bytes.fromhex("a00a06082a8648ce3d030107")
    envelope = bytes([2, 1, 0, KEY_ID, 1]) + short(license_payload(0))
    with tempfile.TemporaryDirectory() as directory:
        private = Path(directory) / "key.der"
        private.write_bytes(key)
        public = run(
            "pkey", "-inform", "DER", "-in", str(private), "-pubout",
            "-outform", "DER", "-ec_conv_form", "compressed",
        )[-33:]
        message = Path(directory) / "message"
        message.write_bytes(b"vouchkit-license-v2\0" + envelope)
        signature = run(
            "dgst", "-sha256", "-keyform", "DER", "-sign", str(private), str(message),
        )
    r, s = read_der_signature(signature)
    low_s = min(s, N - s)
    fixed_signature = r.to_bytes(32, "big") + low_s.to_bytes(32, "big")
    token = envelope + fixed_signature
    (CRATE / "src" / "self-test-p256.bin").write_bytes(token)
    (CRATE / "src" / "self-test-p256.pub").write_bytes(public)
    output = {
        "signing_algorithm": "ecdsa-p256-sha256",
        "master_key_id": KEY_ID,
        "test_only_master_scalar_hex": SEED.hex(),
        "master_public_sec1_hex": public.hex(),
        "verification_time": NOW + 1,
        "expected": "Active",
        "standalone_hex": token.hex(),
        "signature_original_der_hex": signature.hex(),
        "signature_low_s_hex": fixed_signature.hex(),
    }
    (ROOT / "p256.json").write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
