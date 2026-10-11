#!/usr/bin/env python3
"""Independent, deliberately restricted reference for public P02 fixture bytes.

This is not a JCS implementation: fixture property names must be ASCII and all
JSON numbers must be the schema constant 1. Runtime RFC 8785 uses canonicalize.
No signatures, AEAD, authority or retained-history authenticity are verified.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(value):
    if isinstance(value, list):
        value = "".join(value)
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def unhex(value):
    return bytes.fromhex("".join(value) if isinstance(value, list) else value)


def restricted_bytes(value):
    def inspect(item):
        if isinstance(item, dict):
            assert all(key.isascii() for key in item), "Reference only supports ASCII fixture keys"
            for child in item.values():
                inspect(child)
        elif isinstance(item, list):
            for child in item:
                inspect(child)
        elif type(item) in (int, float):
            assert type(item) is int and item == 1, "Reference only supports the numeric schema constant 1"
    inspect(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def domain(family, purpose):
    return f"AnyNote/p02-file-c1/{family}/{purpose}\0".encode()


def digest(purpose, data):
    return hashlib.sha256(domain("hash", purpose) + data).digest()


def check(document):
    assert document["status"] == "PUBLIC_NONSECRET_SERIALIZATION_ONLY"
    assert len(document["cases"]) == 6
    chunks = 0
    for case in document["cases"]:
        source, output = case["input"], case["outputs"]
        for kind in ("context", "wrap", "header", "manifest", "envelope", "checkpoint"):
            assert restricted_bytes(source[kind]) == unhex(output["canonical_hex"][kind]), f"JCS bytes: {kind}"
        for page, expected in zip(source["pages"], output["canonical_hex"]["pages"], strict=True):
            assert restricted_bytes(page) == unhex(expected)
        for kind, purpose in (("header", "file-manifest"), ("checkpoint", "history-checkpoint")):
            assert domain("sign", purpose) + restricted_bytes(source[kind]) == unhex(output[f"{kind}_signing_input_hex"])
        for kind, purpose in (("wrap", "key-wrap"), ("envelope", "file-envelope"), ("checkpoint", "history-checkpoint")):
            assert b64(digest(purpose, restricted_bytes(source[kind]))) == output[f"{kind}_digest"]
        header = source["header"]
        assert header["key_wrap_digest"] == output["wrap_digest"]
        for kind, purpose, extra in (("manifest", "file-manifest", {"framing": header["framing"]}), ("wrap", "file-manifest-key-wrap", {})):
            aad = {"purpose": purpose, "context": source["context"], **extra}
            assert domain("aad", purpose) + restricted_bytes(aad) == unhex(output[f"{kind}_aad_hex"])
        framing = header["framing"]
        size = int(framing["plaintext_bytes"])
        count = (size + 8_388_607) // 8_388_608
        assert int(framing["chunk_count"]) == len(framing["parts"]) == len(output["chunks"]) == count
        for index, chunk in enumerate(output["chunks"]):
            length = min(8_388_608, size - index * 8_388_608)
            assert framing["parts"][index]["index"] == str(index)
            assert int(framing["parts"][index]["ciphertext_bytes"]) == length + 16
            aad = {"purpose": "file-chunk", "context": source["context"], "chunk_index": str(index), "plaintext_chunk_bytes": str(length), "chunk_count": str(count)}
            assert domain("aad", "file-chunk") + restricted_bytes(aad) == unhex(chunk["aad_hex"])
            assert unb64(source["manifest"]["nonce_prefix"]) + struct.pack("<Q", index) == unhex(chunk["nonce_hex"])
            chunks += 1
        descriptor = source["checkpoint"]
        record_count = sum(len(page["records"]) for page in source["pages"])
        assert int(descriptor["record_count"]) == record_count
        assert int(descriptor["page_count"]) == len(source["pages"])
        commitment = domain("hash", "history-inventory") + struct.pack(">IQ", len(source["pages"]), record_count)
        for index, page in enumerate(source["pages"]):
            encoded = restricted_bytes(page)
            commitment += struct.pack(">III", index, len(page["records"]), len(encoded)) + digest("history-page", encoded)
        assert b64(hashlib.sha256(commitment).digest()) == descriptor["inventory_digest"]
    return chunks


def main():
    document = json.loads((ROOT / "fixtures/protocol/p02/vectors.json").read_bytes())
    chunks = check(document)
    # Mutating expected bytes must make the independent check fail. These are
    # disposable memory copies, never an overwrite of committed vectors.
    for field in ("header_signing_input_hex", "wrap_digest"):
        bad = json.loads(json.dumps(document))
        bad["cases"][0]["outputs"][field] = "00" if field.endswith("_hex") else b64(b"wrong")
        try:
            check(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError("Negative reference did not fail")
    print(f"PASS: independent restricted reference: 6 fixtures / {chunks} nonce-AAD pairs / 2 rejection mutations")
    print("Scope: serialization/hash/framing only; native/PHP/physical crypto and authorization NOT RUN")


if __name__ == "__main__":
    main()
