//! PUBLIC interoperability runner, not a product key/authentication endpoint.
use anynote_crypto_core::{
    codec::{self, Codec, canonical, text},
    crypto::*,
    files::{FileReader, FileWriter},
    history::HistoryAnchor,
    local, objects,
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, time::Instant};
type R<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn raw(v: &Value) -> Vec<u8> {
    canonical(v).unwrap()
}
fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn must(ok: bool, checks: &mut usize, name: &str) {
    assert!(ok, "PUBLIC test failed: {name}");
    *checks += 1;
}
struct OwnedDir(PathBuf);
impl Drop for OwnedDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn memory() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}
fn main() -> R<()> {
    let mut args = std::env::args().skip(1);
    let corpus = args.next().ok_or("PUBLIC corpus path required")?;
    let f = codec::strict(&fs::read(corpus)?, 33_554_432)?;
    if f["purpose"] != "PUBLIC_TEST_ONLY_NOT_PRODUCT_AUTHORIZATION" {
        return Err("Wrong test purpose".into());
    }
    let codec = Codec::new()?;
    let mut checks = 0;
    for x in f["jcs"]["valid"].as_array().unwrap() {
        must(
            codec::jcs(&hx(&x["input_hex"]))? == hx(&x["expected_hex"]),
            &mut checks,
            "RFC8785",
        );
    }
    for x in f["jcs"]["invalid_hex"].as_array().unwrap() {
        must(
            codec::jcs(&hx(x)).is_err(),
            &mut checks,
            "malformed raw JSON",
        );
    }
    for x in f["frames"].as_array().unwrap() {
        must(
            codec.encode(text(&x["profile"])?, text(&x["kind"])?, &hx(&x["raw_hex"]))?
                == hx(&x["expected_hex"]),
            &mut checks,
            "frozen schema/bytes",
        );
    }
    for x in f["negatives"].as_array().unwrap() {
        must(
            codec
                .decode(text(&x["profile"])?, text(&x["kind"])?, &hx(&x["raw_hex"]))
                .is_err(),
            &mut checks,
            "invalid closed public frame",
        );
    }
    let public_pair = libsodium_rs::crypto_sign::KeyPair::from_seed(&[1; 32])?;
    let mut public_signatures = vec![];
    for x in f["signed"].as_array().unwrap() {
        let body = codec.decode(text(&x["profile"])?, text(&x["kind"])?, &hx(&x["raw_hex"]))?;
        let signing_bytes = codec.signing(text(&x["profile"])?, text(&x["kind"])?, &body)?;
        must(
            signing_bytes == hx(&x["expected_signing_hex"]),
            &mut checks,
            "public signing bytes",
        );
        let signature = sign(&signing_bytes, public_pair.secret_key.as_ref())?;
        verify(&signing_bytes, &signature, public_pair.public_key.as_ref())?;
        checks += 1;
        public_signatures.push(json!({"profile":x["profile"],"kind":x["kind"],"raw_hex":x["raw_hex"],"canonical_hex":x["expected_hex"],"signing_hex":x["expected_signing_hex"],"signature":signature,"public_key":b64(public_pair.public_key.as_ref())}));
    }
    let i = &f["notes"]["inputs"];
    let o = &f["notes"]["objects"];
    let e = &f["notes"]["expected"];
    let group = hx(&i["group_key_hex"]);
    let signing = hx(&i["signing_secret_hex"]);
    let public = hx(&i["signing_public_hex"]);
    let local_key = hx(&i["local_key_hex"]);
    let prf = hx(&i["prf_result_hex"]);
    let context = raw(&o["payload"]["context"]);
    must(
        objects::open_object(&codec, &raw(&o["bundle"]), &group, &public, &context)?
            == o["payload"],
        &mut checks,
        "frozen object",
    );
    must(
        objects::open_local(
            &codec,
            &raw(&o["local_cipher"]),
            &local_key,
            &raw(&o["local_plain"]["context"]),
        )? == o["local_plain"],
        &mut checks,
        "frozen local",
    );
    let wrong = [254; 32];
    for field in ["group_id", "object_id", "revision_id"] {
        let mut c = o["payload"]["context"].clone();
        c[field] = json!(b64(&[254; 16]));
        must(
            objects::open_object(&codec, &raw(&o["bundle"]), &group, &public, &raw(&c)).is_err(),
            &mut checks,
            "wrong context",
        );
    }
    must(
        objects::open_object(&codec, &raw(&o["bundle"]), &wrong, &public, &context).is_err(),
        &mut checks,
        "wrong key",
    );
    must(
        objects::open_object(&codec, &raw(&o["bundle"]), &group, &wrong, &context).is_err(),
        &mut checks,
        "wrong signer",
    );
    for field in ["signature", "nonce", "ciphertext", "tag"] {
        let mut b = o["bundle"].clone();
        match field {
            "signature" => b["envelope"]["signature"] = json!(b64(&[0; 64])),
            "nonce" => b["envelope"]["header"]["nonce"] = json!(b64(&[0; 24])),
            _ => {
                let mut v = un64(text(&b["ciphertext"])?)?;
                let n = if field == "tag" { v.len() - 1 } else { 0 };
                v[n] ^= 1;
                b["ciphertext"] = json!(b64(&v));
            }
        }
        must(
            objects::open_object(&codec, &raw(&b), &group, &public, &context).is_err(),
            &mut checks,
            "tampered object",
        );
    }
    let phrase = local::phrase_kek(&codec, text(&i["phrase"])?, &raw(&o["parameters"]))?;
    must(
        hex::encode(&phrase) == e["phrase_kek_hex"],
        &mut checks,
        "Argon2id",
    );
    for (field, value) in [
        ("memlimit", 67108863),
        ("memlimit", 268435457),
        ("opslimit", 2),
        ("opslimit", 11),
    ] {
        let mut p = o["parameters"].clone();
        p[field] = json!(value);
        must(
            local::phrase_kek(&codec, text(&i["phrase"])?, &raw(&p)).is_err(),
            &mut checks,
            "KDF bound",
        );
    }
    must(
        local::phrase_kek(&codec, "1234", &raw(&o["parameters"])).is_err(),
        &mut checks,
        "PIN rejected",
    );
    let pk = local::prf_kek(
        &codec,
        &raw(&o["prf_descriptor"]["context"]),
        text(&o["prf_descriptor"]["credential_id"])?,
        &un64(text(&o["prf_descriptor"]["prf_salt"])?)?,
        &prf,
    )?;
    must(
        hex::encode(&pk) == e["prf_kek_hex"],
        &mut checks,
        "PRF HKDF",
    );
    for (kind, d, w, kek) in [
        (
            "phrase-wrapper",
            &o["phrase_descriptor"],
            &o["phrase_wrapper"],
            &phrase,
        ),
        ("prf-wrapper", &o["prf_descriptor"], &o["prf_wrapper"], &pk),
    ] {
        must(
            *local::unwrap(&codec, kind, &raw(w), &raw(d), kek)? == local_key,
            &mut checks,
            "frozen wrapper",
        );
        let fresh = local::wrap(&codec, kind, &raw(d), &local_key, kek)?;
        must(
            *local::unwrap(&codec, kind, &raw(&fresh), &raw(d), kek)? == local_key,
            &mut checks,
            "fresh wrapper",
        );
        must(
            local::unwrap(&codec, kind, &raw(w), &raw(d), &wrong).is_err(),
            &mut checks,
            "wrong KEK",
        );
    }
    let nk = local::native_kek(&codec, &raw(&o["native_descriptor"]), &prf)?;
    must(
        hex::encode(&nk) == e["native_kek_hex"] && *nk != *pk,
        &mut checks,
        "Windows purpose HKDF",
    );
    must(
        *local::unwrap_native(
            &codec,
            &raw(&o["native_wrapper"]),
            &raw(&o["native_descriptor"]),
            &prf,
        )? == local_key,
        &mut checks,
        "frozen AES",
    );
    must(
        local::unwrap_native(
            &codec,
            &raw(&o["native_wrapper"]),
            &raw(&o["native_descriptor"]),
            &wrong,
        )
        .is_err(),
        &mut checks,
        "wrong PRF",
    );
    let id = &f["identity"];
    let secret = hx(&id["input"]["root_secret_hex"]);
    let root_context = raw(&id["input"]["context"]);
    let (root, recovery) = objects::derive_root(&codec, &secret, &root_context)?;
    must(
        b64(root.public_key.as_ref()) == id["outputs"]["identity"]["body"]["root_signing_key"]
            && b64(recovery.public_key.as_ref())
                == id["outputs"]["identity"]["body"]["recovery_encryption_key"],
        &mut checks,
        "root hierarchy",
    );
    must(
        objects::create_identity(&codec, &secret, &root_context)? == id["outputs"]["identity"],
        &mut checks,
        "identity bytes",
    );
    must(
        objects::recovery_encode(&secret)? == id["outputs"]["kit"]["recovery_secret"]
            && *objects::recovery_decode(text(&id["outputs"]["kit"]["recovery_secret"])?)?
                == secret,
        &mut checks,
        "recovery checksum",
    );
    let mut bad = text(&id["outputs"]["kit"]["recovery_secret"])?.to_string();
    let last = bad.pop();
    bad.push(if last == Some('q') { 'p' } else { 'q' });
    must(
        objects::recovery_decode(&bad).is_err(),
        &mut checks,
        "bad recovery checksum",
    );
    objects::recover_root(
        &codec,
        &raw(&id["outputs"]["kit"]),
        &raw(&id["outputs"]["pin"]),
    )?;
    checks += 1;
    for field in ["service_id", "account_id"] {
        let mut ctx = id["input"]["context"].clone();
        ctx[field] = json!(b64(&[253; 16]));
        let (k, _) = objects::derive_root(&codec, &secret, &raw(&ctx))?;
        must(
            k.public_key != root.public_key,
            &mut checks,
            "derivation context",
        );
    }
    let (d1, b1) = device_keys()?;
    let (d2, _) = device_keys()?;
    must(
        d1.public_key.as_ref() != b1.public_key.as_ref() && d1.public_key != d2.public_key,
        &mut checks,
        "independent devices",
    );
    let issuer = libsodium_rs::crypto_sign::KeyPair::from_seed(&hx(
        &id["input"]["device_signing_seed_hex"],
    ))?;
    let receiver = libsodium_rs::crypto_box::KeyPair::from_seed(&hx(
        &id["input"]["receiver_encryption_seed_hex"],
    ))?;
    let group_key: Vec<u8> = (144..176).collect();
    for (n, r) in id["sealed_inputs"].as_array().unwrap().iter().enumerate() {
        let recipient = if n == 0 { &receiver } else { &recovery };
        must(
            *objects::open_grant(
                &codec,
                &raw(r),
                &raw(&id["outputs"]["grant_contexts"][n]),
                issuer.public_key.as_ref(),
                recipient.public_key.as_ref(),
                recipient.secret_key.as_ref(),
            )? == group_key,
            &mut checks,
            "frozen sealed recipients",
        );
    }
    let gctx = &id["outputs"]["grant_contexts"][0];
    let grant = objects::seal_grant(
        &codec,
        &raw(gctx),
        &group_key,
        receiver.public_key.as_ref(),
        issuer.secret_key.as_ref(),
    )?;
    let body = grant["body"].clone();
    let rogue = libsodium_rs::crypto_sign::KeyPair::generate()?;
    let mut rogue_grant = grant.clone();
    rogue_grant["signature"] = json!(sign(
        &codec.signing("p02-identity-c1", "grant-body", &body)?,
        rogue.secret_key.as_ref()
    )?);
    must(
        objects::open_grant(
            &codec,
            &raw(&rogue_grant),
            &raw(gctx),
            issuer.public_key.as_ref(),
            receiver.public_key.as_ref(),
            receiver.secret_key.as_ref(),
        )
        .is_err(),
        &mut checks,
        "decryptable unauthorized sender",
    );
    let mut stale = gctx.clone();
    stale["key_epoch"] = json!("2");
    must(
        objects::open_grant(
            &codec,
            &raw(&grant),
            &raw(&stale),
            issuer.public_key.as_ref(),
            receiver.public_key.as_ref(),
            receiver.secret_key.as_ref(),
        )
        .is_err(),
        &mut checks,
        "stale epoch",
    );
    let h = &f["history"];
    let pages: Vec<_> = h["pages"].as_array().unwrap().iter().map(raw).collect();
    let anchor = HistoryAnchor::verify(
        &codec,
        &raw(&h["record"]),
        &pages,
        text(&h["independent_digest"])?,
        &un64(text(&h["signer_key"])?)?,
    )?;
    anchor.check_object(&codec, &raw(&o["bundle"]["envelope"]), &public)?;
    checks += 1;
    anchor.check_file(&codec, &raw(&o["file_record"]["envelope"]), &public)?;
    checks += 1;
    let mut old = o["bundle"]["envelope"].clone();
    old["header"]["context"]["revision_id"] = json!(b64(&[252; 16]));
    old["signature"] = json!(sign(
        &codec.signing("p02-v1", "header", &old["header"])?,
        &signing
    )?);
    must(
        anchor.check_object(&codec, &raw(&old), &public).is_err(),
        &mut checks,
        "unanchored backdated writer",
    );
    must(
        HistoryAnchor::verify(
            &codec,
            &raw(&h["record"]),
            &pages,
            &b64(&[0; 32]),
            &un64(text(&h["signer_key"])?)?,
        )
        .is_err(),
        &mut checks,
        "independent pin required",
    );
    let file_context = raw(&id["outputs"]["file_context"]);
    let mut file = id["outputs"]["file"].clone();
    file["record_kind"] = json!("file-manifest");
    file.as_object_mut().unwrap().remove("chunks");
    let mut reader = FileReader::open(
        &codec,
        &raw(&file),
        &group_key,
        issuer.public_key.as_ref(),
        &file_context,
    )?;
    must(
        hex::encode(&*reader.decrypt_next(&un64(text(&id["outputs"]["file"]["chunks"][0])?)?)?)
            == id["outputs"]["plaintext_hex"],
        &mut checks,
        "frozen file",
    );
    reader.finish()?;
    checks += 1;
    let mut w = FileWriter::new(&codec, &file_context, 73)?;
    let plain = vec![29; 73];
    let chunk = w.encrypt_next(&plain)?;
    must(
        w.encrypt_next(&[30; 73]).is_err(),
        &mut checks,
        "same-index source change",
    );
    let record = w.finish(
        &codec,
        "PUBLIC résumé.bin",
        "application/octet-stream",
        &group_key,
        issuer.secret_key.as_ref(),
    )?;
    let mut r = FileReader::open(
        &codec,
        &raw(&record),
        &group_key,
        issuer.public_key.as_ref(),
        &file_context,
    )?;
    let mut bad = chunk.clone();
    bad[0] ^= 1;
    must(r.decrypt_next(&bad).is_err(), &mut checks, "corrupt chunk");
    must(*r.decrypt_next(&chunk)? == plain, &mut checks, "fresh file");
    must(
        r.decrypt_next(&chunk).is_err(),
        &mut checks,
        "trailing chunk",
    );
    r.finish()?;
    checks += 1;
    let zero = FileWriter::new(&codec, &file_context, 0)?.finish(
        &codec,
        "empty.bin",
        "application/octet-stream",
        &group_key,
        issuer.secret_key.as_ref(),
    )?;
    FileReader::open(
        &codec,
        &raw(&zero),
        &group_key,
        issuer.public_key.as_ref(),
        &file_context,
    )?
    .finish()?;
    checks += 1;
    must(
        FileWriter::new(&codec, &file_context, 1000000001).is_err(),
        &mut checks,
        "oversize preallocation",
    );
    let bundle = objects::seal_object(&codec, &raw(&o["payload"]), &group, &signing)?;
    let local_record = objects::seal_local(&codec, &raw(&o["local_plain"]), &local_key)?;
    let nw = local::wrap_native(&codec, &raw(&o["native_descriptor"]), &local_key, &prf)?;
    let mut report = json!({"status":"PASS","checks":checks,"frames":f["frames"].as_array().unwrap().len(),"peer":{"public_signatures":public_signatures,"bundle":bundle,"local":local_record,"native_wrapper":nw,"grant":grant,"file":{"record":record,"chunk":b64(&chunk)}}});
    while let Some(mode) = args.next() {
        match mode.as_str() {
            "--peer" => {
                let p = codec::strict(
                    &fs::read(args.next().ok_or("Missing PUBLIC peer path")?)?,
                    16_777_216,
                )?;
                for x in p["public_signatures"].as_array().unwrap() {
                    let bytes = codec.signing(
                        text(&x["profile"])?,
                        text(&x["kind"])?,
                        &codec.decode(
                            text(&x["profile"])?,
                            text(&x["kind"])?,
                            &hx(&x["raw_hex"]),
                        )?,
                    )?;
                    must(
                        bytes == hx(&x["signing_hex"]),
                        &mut checks,
                        "peer public signing bytes",
                    );
                    verify(
                        &bytes,
                        text(&x["signature"])?,
                        &un64(text(&x["public_key"])?)?,
                    )?;
                    checks += 1;
                }
                must(
                    objects::open_object(&codec, &raw(&p["bundle"]), &group, &public, &context)?
                        == o["payload"],
                    &mut checks,
                    "browser -> Rust object",
                );
                must(
                    objects::open_local(
                        &codec,
                        &raw(&p["local"]),
                        &local_key,
                        &raw(&o["local_plain"]["context"]),
                    )? == o["local_plain"],
                    &mut checks,
                    "browser -> Rust local",
                );
                must(
                    *local::unwrap_native(
                        &codec,
                        &raw(&p["native_wrapper"]),
                        &raw(&o["native_descriptor"]),
                        &prf,
                    )? == local_key,
                    &mut checks,
                    "browser -> Rust AES",
                );
                must(
                    *objects::open_grant(
                        &codec,
                        &raw(&p["grant"]),
                        &raw(gctx),
                        issuer.public_key.as_ref(),
                        receiver.public_key.as_ref(),
                        receiver.secret_key.as_ref(),
                    )? == group_key,
                    &mut checks,
                    "browser -> Rust sealed",
                );
                let mut r = FileReader::open(
                    &codec,
                    &raw(&p["file"]["record"]),
                    &group_key,
                    issuer.public_key.as_ref(),
                    &file_context,
                )?;
                must(
                    *r.decrypt_next(&un64(text(&p["file"]["chunk"])?)?)? == plain,
                    &mut checks,
                    "browser -> Rust file",
                );
                r.finish()?;
                checks += 1;
            }
            "--large" => {
                let start = Instant::now();
                let path = std::env::temp_dir().join(format!(
                    "anynote-p05-{}",
                    hex::encode(libsodium_rs::random::bytes(16))
                ));
                fs::create_dir(&path)?;
                let owned = OwnedDir(path);
                let size = 1000000000;
                let mut w = FileWriter::new(&codec, &file_context, size)?;
                let count = 120;
                for n in 0..count {
                    let bytes =
                        libsodium_rs::random::bytes((size - n * 8388608).min(8388608) as usize);
                    fs::write(owned.0.join(n.to_string()), w.encrypt_next(&bytes)?)?;
                }
                let rec = w.finish(
                    &codec,
                    "PUBLIC 1 GB.bin",
                    "application/octet-stream",
                    &group_key,
                    issuer.secret_key.as_ref(),
                )?;
                let mut r = FileReader::open(
                    &codec,
                    &raw(&rec),
                    &group_key,
                    issuer.public_key.as_ref(),
                    &file_context,
                )?;
                let mut total = 0;
                for n in 0..count {
                    let plain = r.decrypt_next(&fs::read(owned.0.join(n.to_string()))?)?;
                    total += plain.len();
                }
                r.finish()?;
                must(total == size as usize, &mut checks, "exact 1GB");
                report["large"] = json!({"status":"PASS","plaintext_bytes":total,"chunks":120,"max_plain_chunk_bytes":8388608,"elapsed_ms":start.elapsed().as_millis(),"peak_process_rss_kib":memory(),"physical_acceptance":false});
            }
            _ => return Err("Unsupported PUBLIC test mode".into()),
        }
    }
    report["checks"] = json!(checks);
    println!("{report}");
    Ok(())
}
