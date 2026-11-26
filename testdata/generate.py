#!/usr/bin/env python3
"""Generate fixed VK1 interoperability vectors using OpenSSL, independent of the Rust codecs."""

from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
CRATE = ROOT.parent / "crates" / "vouchkit-core"
NOW = 1_700_000_000
MASTER = bytes([17]) * 32
DELEGATE = bytes([34]) * 32
DEVICE = bytes([51]) * 32
KEY_ID = 255
PRODUCT = b"vouchkit-self-test"
ENTITLEMENT = bytes([4]) * 16
CERT_ID = bytes([9]) * 16


def uleb(value):
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


def field(value):
    return uleb(len(value)) + value


def maybe_bytes(value):
    return b"\x00" if value is None else b"\x01" + value


def maybe_time(value):
    return maybe_bytes(None if value is None else uleb(value))


def short(value):
    return len(value).to_bytes(2, "big") + value


def pkey(seed):
    return bytes.fromhex("302e020100300506032b657004220420") + seed


def run(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True).stdout


def public(seed):
    with tempfile.TemporaryDirectory() as root:
        key = Path(root) / "key.der"
        key.write_bytes(pkey(seed))
        return run("pkey", "-inform", "DER", "-in", str(key), "-pubout", "-outform", "DER")[-32:]


def sign(domain, body, seed):
    with tempfile.TemporaryDirectory() as root:
        key = Path(root) / "key.der"
        message = Path(root) / "message"
        key.write_bytes(pkey(seed))
        message.write_bytes(domain + b"\x00" + body)
        return body + run(
            "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
            "-inkey", str(key), "-in", str(message),
        )


def license_payload(kind, *, end=None, renew=None, device=None):
    return (
        bytes([kind]) + bytes([1 + kind]) * 16 + ENTITLEMENT
        + field(PRODUCT) + field(b"Fixed vector") + b"\x02"
        + b"\x02\x03\x05" + uleb(1024) + uleb(1050)
        + uleb(NOW) + maybe_time(None) + maybe_time(end) + maybe_time(renew)
        + uleb(60 if kind == 2 else 0)
        + maybe_bytes(uleb(2) + uleb(7) + uleb(0))
        + bytes([2 if kind == 1 else 0]) + maybe_bytes(device)
        + b"\x00\x00\x00"
    )


def encode(payload):
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    bits = "".join(f"{byte:08b}" for byte in payload)
    raw = "".join(alphabet[int(bits[i : i + 5].ljust(5, "0"), 2)] for i in range(0, len(bits), 5))
    return "VK1-" + "-".join(raw[i : i + 5] for i in range(0, len(raw), 5))


def main():
    certificate_payload = (
        CERT_ID + public(DELEGATE) + field(PRODUCT) + uleb(NOW - 60)
        + uleb(NOW + 60) + uleb(900) + b"\x02"
        + b"\x01\x00" + uleb(2047)
    )
    cert = sign(b"vouchkit-delegation-v1", bytes([1, 3, KEY_ID]) + short(certificate_payload), MASTER)
    head = bytes([1, 1, 0, KEY_ID])
    lease_head = bytes([1, 1, 1, KEY_ID])
    crl_payload = (
        uleb(1) + uleb(NOW + 10) + b"\x00" + b"\x01" + ENTITLEMENT
        + b"\x01" + CERT_ID + uleb(NOW + 10)
    )
    vectors = {
        "standalone": sign(b"vouchkit-license-v1", head + short(license_payload(0)), MASTER),
        "entitlement": sign(b"vouchkit-license-v1", head + short(license_payload(1)), MASTER),
        "lease": sign(
            b"vouchkit-license-v1",
            lease_head + short(cert) + short(license_payload(2, end=NOW+600, renew=NOW+300, device=public(DEVICE))),
            DELEGATE,
        ),
        "delegation": cert,
        "crl": sign(b"vouchkit-crl-v1", bytes([1, 2, KEY_ID]) + len(crl_payload).to_bytes(4, "big") + crl_payload, MASTER),
    }
    vectors["bad_signature"] = vectors["standalone"][:-1] + bytes([vectors["standalone"][-1] ^ 1])
    expected = {
        "standalone": "Active", "entitlement": "NeedsActivation", "lease": "Active",
        "delegation": "Authenticated", "crl": "Authenticated", "bad_signature": "BadSignature",
    }
    fixtures = CRATE / "tests" / "fixtures"
    for name, value in vectors.items():
        (fixtures / f"{name}.bin").write_bytes(value)
    (CRATE / "src" / "self-test.bin").write_bytes(vectors["standalone"])
    manifest = {
        "issued_at": NOW,
        "verification_time": NOW + 1,
        "product": PRODUCT.decode(),
        "master_key_id": KEY_ID,
        "test_only_master_seed_hex": MASTER.hex(),
        "test_only_delegate_seed_hex": DELEGATE.hex(),
        "test_only_device_seed_hex": DEVICE.hex(),
        "master_public_hex": public(MASTER).hex(),
        "vectors": {
            name: {"hex": value.hex(), "expected": expected[name]} | (
                {"token": encode(value)} if name not in ("crl", "delegation") else {}
            )
            for name, value in vectors.items()
        },
    }
    (ROOT / "vectors.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
