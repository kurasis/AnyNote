# Pinned Microsoft WebAuthn API header

`webauthn.h` is an unmodified MIT-licensed header from microsoft/webauthn,
commit `ef82c157125a0490e05f6ea82a7adb1b8e1bad08` (API 9). Its original
copyright/license notice is retained; the full [MIT license](LICENSE) is included. This is a test-only independent ABI
reference, never an implementation or a runtime dependency.

Source: https://github.com/microsoft/webauthn/blob/ef82c157125a0490e05f6ea82a7adb1b8e1bad08/webauthn.h
SHA-256: `da82d5be6b90a2706185ae44ad93649bcefc0f89c97ab930ec4e6f0abb7b2283`.

The MSVC C probe measures sizes and every field offset of the types used by
our generated bindings. The native Rust test compares those measurements
with its own layouts. API function pointers are generated from separately
pinned Microsoft metadata by `tools/webauthn-bindings`.
