# Public p02-file-c1 serialization fixtures

Six boundary file sizes: 0, 1, 8 MiB-1, 8 MiB, 8 MiB+1, 1,000,000,000 bytes.
125 exact nonce/AAD pairs. Exact expected bytes use single hex strings; protocol
binary fields/digests use unpadded base64url. Input keys are known sequential
bytes, signatures/ciphertext/digests demonstrate framing only. They are not
usable credentials or valid crypto known-answer vectors. Never use them in
production or claim these fixtures decrypt/sign real files.

Read docs/protocol-v1.md for schema, prefix, key-path and acceptance requirements.
The strict codec reproduces vectors; a separately written restricted Python
fixture reference checks bytes/hash/framing and two intentional bad outputs.
Original RFC 8785 expected outputs supply independent canonicalization cases.
Rust/browser/PHP signature/AEAD/authority verification is pending P05.
