// Runs unchanged in Node and a real dedicated browser worker.
import * as api from "./adapters/core.mjs";
import { sodium } from "./adapters/primitives.mjs";
const c = { ...api, sodium };
import { wire } from "./adapters/codecs/identity-codec.mjs";
import { signingInput, digest } from "./adapters/codecs/protocol-codec.mjs";
const clone = (x) => structuredClone(x),
  hex = (s) => c.Buffer.from(s, "hex");
export async function runSuite(f, peer = null) {
  let checks = 0;
  const must = (v, name) => {
    if (!v) throw Error("P05_TEST_FAILURE:" + name);
    checks++;
  };
  const denied = (fn, name) => {
    let refused = false;
    try {
      fn();
    } catch {
      refused = true;
    }
    must(refused, name);
  };
  const deniedAsync = async (fn, name) => {
    let refused = false;
    try {
      await fn();
    } catch {
      refused = true;
    }
    must(refused, name);
  };
  must(
    f.purpose === "PUBLIC_TEST_ONLY_NOT_PRODUCT_AUTHORIZATION",
    "PUBLIC input",
  );
  for (const x of f.jcs.valid)
    must(
      c.Buffer.from(c.canonicalBytes(hex(x.input_hex))).toString("hex") ===
        x.expected_hex,
      x.name,
    );
  for (const x of f.jcs.invalid_hex)
    denied(() => c.canonicalBytes(hex(x)), "malformed JCS");
  for (const x of f.frames) {
    const raw = hex(x.raw_hex);
    c.decode(x.profile, x.kind, raw);
    must(
      c.Buffer.from(c.canonicalBytes(raw)).toString("hex") === x.expected_hex,
      "frozen " + x.profile + "/" + x.kind,
    );
  }
  for (const x of f.negatives)
    denied(() => c.decode(x.profile, x.kind, hex(x.raw_hex)), x.reason);
  const publicPair = c.sodium.crypto_sign_seed_keypair(
      new Uint8Array(32).fill(1),
    ),
    publicSignatures = [];
  for (const x of f.signed) {
    const bytes = c.publicSigningBytes(x.profile, x.kind, hex(x.raw_hex)),
      signature = c.signPublicFrame(
        x.profile,
        x.kind,
        hex(x.raw_hex),
        publicPair.privateKey,
      );
    must(
      c.Buffer.from(bytes).toString("hex") === x.expected_signing_hex,
      "public signing bytes",
    );
    must(
      !!c.verifyPublicFrame(
        x.profile,
        x.kind,
        hex(x.raw_hex),
        signature,
        publicPair.publicKey,
      ),
      "public signature " + x.profile + "/" + x.kind,
    );
    publicSignatures.push({
      profile: x.profile,
      kind: x.kind,
      raw_hex: x.raw_hex,
      canonical_hex: x.expected_hex,
      signing_hex: x.expected_signing_hex,
      signature,
      public_key: c.b64(publicPair.publicKey),
    });
  }
  c.sodium.memzero(publicPair.privateKey);
  const { inputs: i, objects: o, expected: e } = f.notes;
  const group = hex(i.group_key_hex),
    signing = hex(i.signing_secret_hex),
    pub = hex(i.signing_public_hex),
    local = hex(i.local_key_hex),
    prf = hex(i.prf_result_hex),
    ctx = wire(o.payload.context);
  must(
    c.Buffer.from(
      c.canonicalBytes(wire(c.openObject(wire(o.bundle), group, pub, ctx))),
    ).toString() ===
      c.Buffer.from(c.canonicalBytes(wire(o.payload))).toString(),
    "frozen note",
  );
  must(
    c.openLocal(wire(o.local_cipher), local, wire(o.local_plain.context))
      .context.record_kind === o.local_plain.context.record_kind,
    "frozen local",
  );
  for (const field of ["group_id", "revision_id", "object_id"]) {
    const bad = clone(o.payload.context);
    bad[field] = c.b64(new Uint8Array(16).fill(254));
    denied(
      () => c.openObject(wire(o.bundle), group, pub, wire(bad)),
      "changed " + field,
    );
  }
  const wrong = new Uint8Array(32).fill(254);
  denied(
    () => c.openObject(wire(o.bundle), wrong, pub, ctx),
    "wrong group key",
  );
  denied(
    () => c.openObject(wire(o.bundle), group, wrong, ctx),
    "wrong signing key",
  );
  for (const target of ["signature", "nonce", "ciphertext", "tag"]) {
    const b = clone(o.bundle);
    if (target === "signature")
      b.envelope.signature = c.b64(new Uint8Array(64));
    else if (target === "nonce")
      b.envelope.header.nonce = c.b64(new Uint8Array(24));
    else {
      const v = c.un64(b.ciphertext);
      v[target === "tag" ? v.length - 1 : 0] ^= 1;
      b.ciphertext = c.b64(v);
    }
    denied(() => c.openObject(wire(b), group, pub, ctx), "changed " + target);
  }
  // Re-sign framing/digests so these cases reach AEAD rather than fail a public hash.
  for (const target of ["nonce", "tag", "wrap"]) {
    const b = clone(o.bundle);
    if (target === "nonce") b.envelope.header.nonce = c.b64(new Uint8Array(24));
    else if (target === "tag") {
      const x = c.un64(b.ciphertext);
      x[x.length - 1] ^= 1;
      b.ciphertext = c.b64(x);
      b.envelope.header.ciphertext_digest = c.hash(x);
    } else {
      const x = c.un64(b.wrap.ciphertext);
      x[x.length - 1] ^= 1;
      b.wrap.ciphertext = c.b64(x);
      b.envelope.header.key_wrap_digest = digest("wrap", wire(b.wrap));
    }
    b.envelope.signature = c.signPublicFrame(
      "p02-v1",
      "header",
      wire(b.envelope.header),
      signing,
    );
    let code;
    try {
      c.openObject(wire(b), group, pub, ctx);
    } catch (e) {
      code = e.code;
    }
    must(code === "INTEGRITY_FAILURE", "AEAD " + target);
  }
  for (const altered of ["unknown-field", "inner-context"]) {
    const p = clone(o.payload),
      b = clone(o.bundle);
    if (altered === "unknown-field") p.extra = true;
    else p.context.object_id = c.b64(new Uint8Array(16).fill(249));
    const plain = wire(p),
      cipher = c.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plain,
        new TextEncoder().encode(
          "AnyNote/p02-v1/aad/object-payload\0" +
            new TextDecoder().decode(
              c.canonicalBytes(wire({ context: o.payload.context })),
            ),
        ),
        null,
        c.un64(b.envelope.header.nonce),
        hex(i.object_key_hex),
      );
    b.ciphertext = c.b64(cipher);
    b.envelope.header.ciphertext_bytes = String(cipher.length);
    b.envelope.header.ciphertext_digest = c.hash(cipher);
    b.envelope.signature = c.signPublicFrame(
      "p02-v1",
      "header",
      wire(b.envelope.header),
      signing,
    );
    denied(
      () => c.openObject(wire(b), group, pub, ctx),
      "authenticated invalid payload " + altered,
    );
  }
  const encrypted = c.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    new Uint8Array([1]),
    new Uint8Array([2]),
    null,
    new Uint8Array(24),
    local,
  );
  denied(
    () =>
      c.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        encrypted,
        new Uint8Array([3]),
        new Uint8Array(24),
        local,
      ),
    "wrong AEAD AAD",
  );
  const fresh = c.sealObject(wire(o.payload), group, signing);
  must(
    c.openObject(wire(fresh), group, pub, ctx).title === o.payload.title,
    "fresh note",
  );
  must(
    fresh.envelope.header.nonce !== o.bundle.envelope.header.nonce &&
      fresh.wrap.nonce !== o.bundle.wrap.nonce,
    "fresh object nonces",
  );
  const lc = c.sealLocal(wire(o.local_plain), local);
  must(
    c.openLocal(lc, local, wire(o.local_plain.context)).context.record_kind ===
      o.local_plain.context.record_kind,
    "fresh local",
  );
  for (const kind of ["parameters", "phrase_descriptor", "prf_descriptor"])
    must(!!o[kind], kind);
  const first = c.phraseKek(i.phrase, wire(o.parameters));
  await deniedAsync(
    () => c.phraseKek(i.phrase, wire(o.parameters)),
    "one KDF at a time",
  );
  const phrase = await first;
  must(
    c.Buffer.from(phrase).toString("hex") === e.phrase_kek_hex,
    "Argon2id exact bytes",
  );
  for (const [field, n] of [
    ["memlimit", 67108863],
    ["memlimit", 268435457],
    ["opslimit", 2],
    ["opslimit", 11],
  ]) {
    const p = clone(o.parameters);
    p[field] = n;
    await deniedAsync(
      () => c.phraseKek(i.phrase, wire(p)),
      "KDF preallocation bound",
    );
  }
  await deniedAsync(
    () => c.phraseKek("1234", wire(o.parameters)),
    "short PIN denied",
  );
  const pk = await c.prfKek(
    wire(o.prf_descriptor.context),
    o.prf_descriptor.credential_id,
    c.un64(o.prf_descriptor.prf_salt),
    prf,
  );
  must(c.Buffer.from(pk).toString("hex") === e.prf_kek_hex, "PRF exact bytes");
  for (const [kind, d, kek, old] of [
    ["phrase-wrapper", o.phrase_descriptor, phrase, o.phrase_wrapper],
    ["prf-wrapper", o.prf_descriptor, pk, o.prf_wrapper],
  ]) {
    must(
      c.b64(c.unwrapLocalKey(kind, wire(old), wire(d), kek)) === c.b64(local),
      "frozen " + kind,
    );
    const w = c.wrapLocalKey(kind, wire(d), local, kek);
    must(
      c.b64(c.unwrapLocalKey(kind, w, wire(d), kek)) === c.b64(local),
      "fresh " + kind,
    );
    denied(
      () => c.unwrapLocalKey(kind, wire(old), wire(d), wrong),
      "wrong wrapper KEK",
    );
  }
  const nk = await c.nativeKek(wire(o.native_descriptor), prf);
  must(
    c.Buffer.from(nk).toString("hex") === e.native_kek_hex,
    "Windows-purpose HKDF bytes",
  );
  must(c.b64(nk) !== c.b64(pk), "PRF purposes separated");
  must(
    c.b64(
      await c.unwrapNative(
        wire(o.native_wrapper),
        wire(o.native_descriptor),
        prf,
      ),
    ) === c.b64(local),
    "frozen native wrapper",
  );
  const nw = await c.wrapNative(wire(o.native_descriptor), local, prf);
  must(
    c.b64(await c.unwrapNative(nw, wire(o.native_descriptor), prf)) ===
      c.b64(local),
    "fresh native wrapper",
  );
  await deniedAsync(
    () =>
      c.unwrapNative(wire(o.native_wrapper), wire(o.native_descriptor), wrong),
    "wrong native PRF",
  );
  const id = f.identity,
    root = await c.deriveRoot(
      hex(id.input.root_secret_hex),
      wire(id.input.context),
    );
  must(
    c.b64(root.signing.publicKey) ===
      id.outputs.identity.body.root_signing_key &&
      c.b64(root.recovery.publicKey) ===
        id.outputs.identity.body.recovery_encryption_key,
    "recovery hierarchy",
  );
  must(
    c.Buffer.from(
      await c.createIdentity(
        hex(id.input.root_secret_hex),
        wire(id.input.context),
      ),
    ).toString("hex") === id.outputs.identity_canonical_hex,
    "identity exact bytes",
  );
  must(
    c.b64(
      c.decodeRecoverySecret(
        c.encodeRecoverySecret(hex(id.input.root_secret_hex)),
      ),
    ) === c.b64(hex(id.input.root_secret_hex)),
    "recovery encoding",
  );
  denied(
    () =>
      c.decodeRecoverySecret(
        id.outputs.kit.recovery_secret.slice(0, -1) +
          (id.outputs.kit.recovery_secret.endsWith("q") ? "p" : "q"),
      ),
    "recovery checksum",
  );
  const recovered = await c.recoverRoot(
    wire(id.outputs.kit),
    wire(id.outputs.pin),
  );
  must(
    c.b64(recovered.recovery.publicKey) ===
      id.outputs.identity.body.recovery_encryption_key,
    "pinned kit",
  );
  for (const field of ["service_id", "account_id"]) {
    const altered = clone(id.input.context);
    altered[field] = c.b64(new Uint8Array(16).fill(253));
    const k = await c.deriveRoot(hex(id.input.root_secret_hex), wire(altered));
    must(
      c.b64(k.signing.publicKey) !== c.b64(root.signing.publicKey),
      "HKDF " + field,
    );
    c.sodium.memzero(k.signing.privateKey);
    c.sodium.memzero(k.recovery.privateKey);
  }
  const d1 = c.deviceKeys(),
    d2 = c.deviceKeys();
  must(
    c.b64(d1.signing.publicKey) !== c.b64(d1.encryption.publicKey) &&
      c.b64(d1.signing.publicKey) !== c.b64(d2.signing.publicKey),
    "independent device keys",
  );
  const issuer = c.sodium.crypto_sign_seed_keypair(
      hex(id.input.device_signing_seed_hex),
    ),
    receiver = c.sodium.crypto_box_seed_keypair(
      hex(id.input.receiver_encryption_seed_hex),
    );
  for (let n = 0; n < id.sealed_inputs.length; n++) {
    const keys = n === 0 ? receiver : root.recovery;
    const out = c.openGrant(
      wire(id.sealed_inputs[n]),
      wire(id.outputs.grant_contexts[n]),
      issuer.publicKey,
      keys.publicKey,
      keys.privateKey,
    );
    must(
      c.b64(out) ===
        c.b64(Uint8Array.from({ length: 32 }, (_, i) => (144 + i) % 256)),
      "frozen recipient",
    );
    c.sodium.memzero(out);
  }
  const gctx = wire(id.outputs.grant_contexts[0]),
    gkey = Uint8Array.from({ length: 32 }, (_, i) => (144 + i) % 256),
    grant = c.sealGrant(gctx, gkey, receiver.publicKey, issuer.privateKey);
  must(
    c.b64(
      c.openGrant(
        grant,
        gctx,
        issuer.publicKey,
        receiver.publicKey,
        receiver.privateKey,
      ),
    ) === c.b64(gkey),
    "fresh signed recipient",
  );
  const rogue = c.sodium.crypto_sign_keypair();
  const rogueGrant = c.sealGrant(
    gctx,
    gkey,
    receiver.publicKey,
    rogue.privateKey,
  );
  denied(
    () =>
      c.openGrant(
        rogueGrant,
        gctx,
        issuer.publicKey,
        receiver.publicKey,
        receiver.privateKey,
      ),
    "decryptable unauthorized sender",
  );
  const inner = clone(id.outputs.grant_contexts[0]);
  inner.key_epoch = "2";
  const wrongInnerBody = {
      context: id.outputs.grant_contexts[0],
      sealed_ciphertext: c.b64(
        c.sodium.crypto_box_seal(
          wire({
            purpose: "group-key-plaintext",
            context: inner,
            group_key: c.b64(gkey),
          }),
          receiver.publicKey,
        ),
      ),
    },
    wrongInner = wire({
      body: wrongInnerBody,
      signature: c.signPublicFrame(
        "p02-identity-c1",
        "grant-body",
        wire(wrongInnerBody),
        issuer.privateKey,
      ),
    });
  let innerCode;
  try {
    c.openGrant(
      wrongInner,
      gctx,
      issuer.publicKey,
      receiver.publicKey,
      receiver.privateKey,
    );
  } catch (e) {
    innerCode = e.code;
  }
  must(innerCode === "INNER_CONTEXT_MISMATCH", "sealed inner context");
  for (const length of [0, 31, 33])
    denied(
      () => c.sealObject(wire(o.payload), new Uint8Array(length), signing),
      "invalid key length",
    );
  const stale = clone(id.outputs.grant_contexts[0]);
  stale.key_epoch = "2";
  denied(
    () =>
      c.openGrant(
        grant,
        wire(stale),
        issuer.publicKey,
        receiver.publicKey,
        receiver.privateKey,
      ),
    "stale recipient epoch",
  );
  const unicodeKek = await c.phraseKek(
    i.phrase.replaceAll(" ", "\uFEFF"),
    wire(o.parameters),
  );
  const unicodeWrapper = c.wrapLocalKey(
    "phrase-wrapper",
    wire(o.phrase_descriptor),
    local,
    unicodeKek,
  );
  await deniedAsync(
    () =>
      c.phraseKek(
        "alpha\u0085bravo\u0085charlie\u0085delta\u0085echo",
        wire(o.parameters),
      ),
    "ECMAScript phrase strength whitespace",
  );
  const h = f.history,
    anchor = new c.HistoryAnchor(
      wire(h.record),
      h.pages.map(wire),
      h.independent_digest,
      c.un64(h.signer_key),
    );
  must(anchor.checkObject(wire(o.bundle.envelope), pub), "anchored history");
  must(
    anchor.checkFile(wire(o.file_record.envelope), pub),
    "anchored file history",
  );
  const backdated = clone(o.bundle.envelope);
  backdated.header.context.revision_id = c.b64(new Uint8Array(16).fill(252));
  backdated.signature = c.b64(
    c.sodium.crypto_sign_detached(
      signingInput("header", wire(backdated.header)),
      signing,
    ),
  );
  denied(
    () => anchor.checkObject(wire(backdated), pub),
    "valid retired-policy signature without anchor",
  );
  denied(
    () =>
      new c.HistoryAnchor(
        wire(h.record),
        h.pages.map(wire),
        c.b64(new Uint8Array(32)),
        c.un64(h.signer_key),
      ),
    "server checkpoint is not independent pin",
  );
  const filectx = wire(id.outputs.file_context),
    fileKey = gkey;
  const fr = new c.FileReader(
    wire({
      record_kind: "file-manifest",
      envelope: id.outputs.file.envelope,
      wrap: id.outputs.file.wrap,
      manifest_ciphertext: id.outputs.file.manifest_ciphertext,
    }),
    fileKey,
    issuer.publicKey,
    filectx,
  );
  must(
    c.Buffer.from(fr.decryptNext(c.un64(id.outputs.file.chunks[0]))).toString(
      "hex",
    ) === id.outputs.plaintext_hex,
    "frozen file",
  );
  must(fr.finish().complete, "frozen file completion");
  const fw = new c.FileWriter(filectx, 73),
    plain = new Uint8Array(73).fill(29),
    chunk = fw.encryptNext(plain);
  denied(
    () => fw.encryptNext(new Uint8Array(73).fill(30)),
    "source-change same-index retry",
  );
  const record = fw.finish(
    "PUBLIC résumé.bin",
    "application/octet-stream",
    fileKey,
    issuer.privateKey,
  );
  const rd = new c.FileReader(wire(record), fileKey, issuer.publicKey, filectx);
  denied(() => rd.finish(), "missing chunk");
  const corrupt = new Uint8Array(chunk);
  corrupt[0] ^= 1;
  denied(() => rd.decryptNext(corrupt), "corrupt chunk");
  must(c.b64(rd.decryptNext(chunk)) === c.b64(plain), "fresh file");
  denied(() => rd.decryptNext(chunk), "trailing chunk");
  must(rd.finish().complete, "complete file");
  const zero = new c.FileWriter(filectx, 0).finish(
    "empty.bin",
    "application/octet-stream",
    fileKey,
    issuer.privateKey,
  );
  must(
    new c.FileReader(wire(zero), fileKey, issuer.publicKey, filectx).finish()
      .complete,
    "zero file authenticated manifest",
  );
  denied(
    () => new c.FileWriter(filectx, 1000000001),
    "oversize before allocation",
  );
  if (peer) {
    must(
      c.b64(
        c.unwrapLocalKey(
          "phrase-wrapper",
          wire(peer.unicode_phrase_wrapper),
          wire(o.phrase_descriptor),
          unicodeKek,
        ),
      ) === c.b64(local),
      "Rust -> browser UTF8 phrase bytes and strength",
    );
    for (const x of peer.public_signatures) {
      must(
        c.sodium.crypto_sign_verify_detached(
          c.un64(x.signature),
          hex(x.signing_hex),
          c.un64(x.public_key),
        ),
        "Rust public sign",
      );
      must(
        publicSignatures.some(
          (p) =>
            p.profile === x.profile &&
            p.kind === x.kind &&
            p.signature === x.signature &&
            p.signing_hex === x.signing_hex,
        ),
        "Rust/browser public bytes",
      );
    }
    must(
      c.openObject(wire(peer.bundle), group, pub, ctx).title ===
        o.payload.title,
      "Rust -> browser note",
    );
    must(
      c.openLocal(wire(peer.local), local, wire(o.local_plain.context)).context
        .record_kind === o.local_plain.context.record_kind,
      "Rust -> browser local",
    );
    must(
      c.b64(
        await c.unwrapNative(
          wire(peer.native_wrapper),
          wire(o.native_descriptor),
          prf,
        ),
      ) === c.b64(local),
      "Rust -> browser AES",
    );
    must(
      c.b64(
        c.openGrant(
          wire(peer.grant),
          gctx,
          issuer.publicKey,
          receiver.publicKey,
          receiver.privateKey,
        ),
      ) === c.b64(gkey),
      "Rust -> browser recipient",
    );
    const r = new c.FileReader(
      wire(peer.file.record),
      fileKey,
      issuer.publicKey,
      filectx,
    );
    must(
      c.b64(r.decryptNext(c.un64(peer.file.chunk))) === c.b64(plain),
      "Rust -> browser file",
    );
    must(r.finish().complete, "Rust file complete");
  }
  for (const s of [
    unicodeKek,
    phrase,
    pk,
    nk,
    root.signing.privateKey,
    root.recovery.privateKey,
    recovered.signing.privateKey,
    recovered.recovery.privateKey,
    issuer.privateKey,
    receiver.privateKey,
    rogue.privateKey,
    d1.signing.privateKey,
    d1.encryption.privateKey,
    d2.signing.privateKey,
    d2.encryption.privateKey,
  ])
    c.sodium.memzero(s);
  return {
    status: "PASS",
    checks,
    frames: f.frames.length,
    jcs: f.jcs.valid.length,
    peer: {
      unicode_phrase_wrapper: JSON.parse(
        c.Buffer.from(unicodeWrapper).toString(),
      ),
      public_signatures: publicSignatures,
      bundle: fresh,
      local: JSON.parse(c.Buffer.from(lc).toString()),
      native_wrapper: JSON.parse(c.Buffer.from(nw).toString()),
      grant: JSON.parse(c.Buffer.from(grant).toString()),
      file: { record, chunk: c.b64(chunk) },
    },
  };
}
