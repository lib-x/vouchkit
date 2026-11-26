# Interoperability vectors

`vectors.json` records the token text, signed binary bytes, test-only private seeds and expected outcomes. Run `python testdata/generate.py` with OpenSSL available to regenerate the vectors using an independent Ed25519 implementation. The generator uses fixed data so it must never be used for production credentials.

`p256.json` adds an external OpenSSL ECDSA P-256 signature. `python testdata/generate_p256.py` regenerates it. Its public key and claims remain fixed. OpenSSL may use a fresh ECDSA nonce, so a newly generated valid signature can differ from the checked-in fixture.
