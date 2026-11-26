# Interoperability vectors

`vectors.json` records the token text, signed binary bytes, test-only private seeds and expected outcomes. Run `python testdata/generate.py` with OpenSSL available to regenerate the vectors using an independent Ed25519 implementation. The generator uses fixed data so it must never be used for production credentials.
