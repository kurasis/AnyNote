import {
  sodium,
  Buffer,
  b64,
  un64,
  key,
  hash,
  encrypt,
  decrypt,
  randomKey,
} from "./primitives.mjs";
import { createHash } from "./bytes.mjs";
import { wire, same } from "./codecs/identity-codec.mjs";
import {
  decode,
  encode,
  signingInput,
  fileAad,
  chunkNonce,
  wrapDigest,
  checkManifestCiphertext,
  checkFileBundle,
} from "./codecs/codec.mjs";
import { decode as completeDecode } from "./codecs/protocol-codec.mjs";
import { requireCondition as check } from "../src/strict-json.mjs";
const CHUNK = 8388608;
export class FileWriter {
  #context;
  #size;
  #next = 0;
  #parts = [];
  #fileKey;
  #manifestKey;
  #prefix;
  #digest = createHash("sha256");
  #closed = false;
  #sourceDigest;
  constructor(contextBytes, size) {
    check(
      Number.isSafeInteger(size) && size >= 0 && size <= 1000000000,
      "RESOURCE_LIMIT",
    );
    this.#context = decode("context", contextBytes);
    this.#size = size;
    this.#fileKey = randomKey();
    this.#manifestKey = randomKey();
    this.#prefix = sodium.randombytes_buf(16);
  }
  // Only protected custody persists these secrets inside its encrypted local journal.
  checkpoint() {
    check(!this.#closed, 'INCOMPLETE_FILE');
    return {context:this.#context,size:this.#size,next:this.#next,parts:this.#parts,
      file_key:b64(this.#fileKey),manifest_key:b64(this.#manifestKey),prefix:b64(this.#prefix),source_digest:this.#sourceDigest??null};
  }
  static resume(state) {
    const w=new FileWriter(wire(state.context),state.size);
    check(Number.isSafeInteger(state.next)&&state.next>=0&&state.next<=Math.ceil(state.size/CHUNK)&&state.parts.length===state.next,'INVALID_CHUNK_INDEX');
    sodium.memzero(w.#fileKey);sodium.memzero(w.#manifestKey);
    w.#fileKey=un64(state.file_key);w.#manifestKey=un64(state.manifest_key);w.#prefix=un64(state.prefix);
    key(w.#fileKey);key(w.#manifestKey);check(w.#prefix.length===16,'INVALID_NONCE');
    w.#next=state.next;w.#parts=structuredClone(state.parts);w.#sourceDigest=state.source_digest;
    check(typeof w.#sourceDigest==='string'&&un64(w.#sourceDigest).length===32,'SOURCE_IDENTITY_REQUIRED');
    return w;
  }
  bindSource(digest) {check(this.#next===0&&typeof digest==='string'&&un64(digest).length===32,'SOURCE_IDENTITY_REQUIRED');this.#sourceDigest=digest;}
  #header() {
    return {
      purpose: "file-manifest",
      context: this.#context,
      framing: {
        plaintext_bytes: String(this.#size),
        chunk_plaintext_bytes: String(CHUNK),
        chunk_count: String(Math.ceil(this.#size / CHUNK)),
        parts: this.#parts,
      },
      manifest_nonce: b64(new Uint8Array(24)),
      manifest_ciphertext_bytes: "16",
      manifest_ciphertext_digest: hash(new Uint8Array()),
      key_wrap_digest: hash(new Uint8Array()),
    };
  }
  encryptNext(plain) {
    check(
      !this.#closed && this.#next < Math.ceil(this.#size / CHUNK),
      "INVALID_CHUNK_INDEX",
    );
    check(
      plain instanceof Uint8Array &&
        plain.length === Math.min(CHUNK, this.#size - this.#next * CHUNK),
      "INVALID_CHUNK_LENGTH",
    );
    // Chunk AAD depends only on immutable context/length/count, not unfinished digests.
    const h = this.#header();
    h.framing.parts = Array.from(
      { length: Math.ceil(this.#size / CHUNK) },
      (_, i) => ({
        index: String(i),
        ciphertext_bytes: String(Math.min(CHUNK, this.#size - i * CHUNK) + 16),
        ciphertext_digest: hash(new Uint8Array()),
      }),
    );
    const cipher = encrypt(
      plain,
      fileAad(wire(h), "chunk-aad", BigInt(this.#next)),
      chunkNonce(this.#prefix, BigInt(this.#next)),
      this.#fileKey,
    );
    this.#digest.update(plain);
    this.#parts.push({
      index: String(this.#next),
      ciphertext_bytes: String(cipher.length),
      ciphertext_digest: hash(cipher),
    });
    this.#next++;
    return cipher;
  }
  finish(name, media, groupKey, signingKey) {
    check(
      !this.#closed && this.#next === Math.ceil(this.#size / CHUNK),
      "INCOMPLETE_FILE",
    );
    key(groupKey);
    key(signingKey, 64);
    try {
      const h = this.#header(),
        wn = sodium.randombytes_buf(24),
        mn = sodium.randombytes_buf(24);
      const manifest = {
        purpose: "file-manifest-plaintext",
        context: this.#context,
        framing: h.framing,
        file_data_key: b64(this.#fileKey),
        nonce_prefix: b64(this.#prefix),
        original_name: name,
        client_media_type: media,
        plaintext_digest: this.#sourceDigest??this.#digest.digest("base64url"),
      };
      const plain = encode("manifest", wire(manifest));
      let cipher;
      try {
        cipher = encrypt(
          plain,
          fileAad(wire(h), "manifest-aad"),
          mn,
          this.#manifestKey,
        );
      } finally {
        sodium.memzero(plain);
      }
      const wrap = {
        purpose: "file-manifest-key-wrap",
        context: this.#context,
        nonce: b64(wn),
        ciphertext: b64(
          encrypt(
            this.#manifestKey,
            fileAad(wire(h), "wrap-aad"),
            wn,
            groupKey,
          ),
        ),
      };
      Object.assign(h, {
        manifest_nonce: b64(mn),
        manifest_ciphertext_bytes: String(cipher.length),
        manifest_ciphertext_digest: hash(cipher),
        key_wrap_digest: wrapDigest(wire(wrap)),
      });
      return {
        record_kind: "file-manifest",
        envelope: decode(
          "envelope",
          wire({
            header: h,
            signature: b64(
              sodium.crypto_sign_detached(
                signingInput("header", wire(h)),
                signingKey,
              ),
            ),
          }),
        ),
        wrap,
        manifest_ciphertext: b64(cipher),
      };
    } finally {
      this.close();
    }
  }
  close() {
    if (!this.#closed) {
      sodium.memzero(this.#fileKey);
      sodium.memzero(this.#manifestKey);
      this.#closed = true;
    }
  }
}
export class FileReader {
  #header;
  #manifest;
  #fileKey;
  #prefix;
  #next = 0;
  #closed = false;
  #digest = createHash("sha256");
  metadata() {return {name:this.#manifest.original_name,media:this.#manifest.client_media_type};}
  constructor(recordBytes, groupKey, publicKey, contextBytes) {
    const record = completeDecode("export-file-record", recordBytes);
    key(groupKey);
    key(publicKey);
    const e = decode("envelope", wire(record.envelope)),
      h = e.header;
    const expected = decode("context", contextBytes);
    check(same(h.context, expected), "CONTEXT_MISMATCH");
    check(
      sodium.crypto_sign_verify_detached(
        un64(e.signature),
        signingInput("header", wire(h)),
        publicKey,
      ),
      "INVALID_SIGNATURE",
    );
    const w = decode("wrap", wire(record.wrap));
    check(
      same(w.context, expected) && wrapDigest(wire(w)) === h.key_wrap_digest,
      "KEY_WRAP_MISMATCH",
    );
    const cipher = un64(record.manifest_ciphertext);
    checkManifestCiphertext(wire(h), cipher);
    const mk = decrypt(
      un64(w.ciphertext),
      fileAad(wire(h), "wrap-aad"),
      un64(w.nonce),
      groupKey,
    );
    let plain;
    try {
      plain = decrypt(
        cipher,
        fileAad(wire(h), "manifest-aad"),
        un64(h.manifest_nonce),
        mk,
      );
      const m = decode("manifest", plain);
      checkFileBundle(wire(h), wire(w), plain, contextBytes);
      this.#fileKey = un64(m.file_data_key);
      this.#prefix = un64(m.nonce_prefix);
      delete m.file_data_key;
      this.#manifest = m;
      this.#header = h;
    } finally {
      sodium.memzero(mk);
      if (plain) sodium.memzero(plain);
    }
  }
  decryptNext(cipher) {
    check(
      !this.#closed && this.#next < Number(this.#header.framing.chunk_count),
      "INVALID_CHUNK_INDEX",
    );
    const plain=this.decryptAt(this.#next,cipher);
    this.#digest.update(plain);
    this.#next++;
    return plain;
  }
  decryptAt(index,cipher) {
    check(!this.#closed&&Number.isSafeInteger(index)&&index>=0&&index<Number(this.#header.framing.chunk_count),'INVALID_CHUNK_INDEX');
    const p = this.#header.framing.parts[index];
    check(
      cipher instanceof Uint8Array &&
        cipher.length === Number(p.ciphertext_bytes) &&
        hash(cipher) === p.ciphertext_digest,
      "CHUNK_DIGEST_MISMATCH",
    );
    const plain = decrypt(
      cipher,
      fileAad(wire(this.#header), "chunk-aad", BigInt(index)),
      chunkNonce(this.#prefix, BigInt(index)),
      this.#fileKey,
    );
    return plain;
  }
  finish() {
    check(
      !this.#closed && this.#next === Number(this.#header.framing.chunk_count),
      "INCOMPLETE_FILE",
    );
    try {
      if (this.#manifest.plaintext_digest !== null)
        check(
          this.#digest.digest("base64url") === this.#manifest.plaintext_digest,
          "PLAINTEXT_MISMATCH",
        );
      return {
        complete: true,
        plaintext_bytes: this.#header.framing.plaintext_bytes,
      };
    } finally {
      this.close();
    }
  }
  close() {
    if (!this.#closed) {
      if (this.#fileKey) sodium.memzero(this.#fileKey);
      this.#closed = true;
    }
  }
}
