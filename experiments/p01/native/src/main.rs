//! Isolated P01 experiment. All emitted fixture keys are PUBLIC/NONSECRET.
//! This is not AnyNote's application protocol, authorization or key custody.
mod kdf;
use libsodium_rs::{
    crypto_aead::xchacha20poly1305 as aead, crypto_box, crypto_hash::sha256, crypto_sign,
    ensure_init, random, version,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_FILE: usize = 1_000_000_000;
const CHUNK: usize = 8_388_608;
const WARNING: &str = "PUBLIC NONSECRET SYNTHETIC P01 FIXTURE; NEVER USE THESE KEYS";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AeadCase {
    key: String,
    nonce: String,
    aad: String,
    message: String,
    ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignCase {
    seed: String,
    public_key: String,
    message: String,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoxCase {
    seed: String,
    public_key: String,
    message: String,
    ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    fixture_version: u32,
    warning: String,
    origin: String,
    sodium_version: String,
    aead: Vec<AeadCase>,
    sign: SignCase,
    sealed_box: BoxCase,
}

fn bytes(s: &str) -> Result<Vec<u8>> {
    if s.len() > 131_072
        || !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid or oversized lowercase hex fixture".into());
    }
    Ok(hex::decode(s)?)
}
fn altered(s: &[u8]) -> Vec<u8> {
    if s.is_empty() {
        return vec![1];
    }
    let mut v = s.to_vec();
    v[0] ^= 1;
    v
}
fn check(condition: bool, name: &str, checks: &mut Vec<String>) -> Result<()> {
    if !condition {
        return Err(format!("failed: {name}").into());
    }
    checks.push(name.to_owned());
    Ok(())
}

fn emit() -> Result<Fixture> {
    let key = aead::Key::from_bytes(&(0..32).collect::<Vec<u8>>())?;
    let mut cases = Vec::new();
    for (index, length) in [0, 1, 31, 1024].into_iter().enumerate() {
        let mut n = [0x42; 24];
        n[23] = index as u8;
        let nonce = aead::Nonce::from_bytes(n);
        let message: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        let aad = format!("anynote/p01/primitive-only/aead/{index}").into_bytes();
        let encrypted = aead::encrypt(&message, Some(&aad), &nonce, &key)?;
        cases.push(AeadCase {
            key: hex::encode(key.as_bytes()),
            nonce: hex::encode(n),
            aad: hex::encode(aad),
            message: hex::encode(message),
            ciphertext: hex::encode(encrypted),
        });
    }
    let sign_seed = [0x53; 32];
    let signer = crypto_sign::KeyPair::from_seed(&sign_seed)?;
    let sign_message = b"anynote/p01/signature/public synthetic data";
    let box_seed = [0x62; 32];
    let recipient = crypto_box::KeyPair::from_seed(&box_seed)?;
    let box_message = b"anynote/p01/sealed-box/public synthetic key";
    Ok(Fixture {
        fixture_version: 1,
        warning: WARNING.to_owned(),
        origin: "rust".to_owned(),
        sodium_version: version::version_string().to_owned(),
        aead: cases,
        sign: SignCase {
            seed: hex::encode(sign_seed),
            public_key: hex::encode(signer.public_key.as_bytes()),
            message: hex::encode(sign_message),
            signature: hex::encode(crypto_sign::sign_detached(
                sign_message,
                &signer.secret_key,
            )?),
        },
        sealed_box: BoxCase {
            seed: hex::encode(box_seed),
            public_key: hex::encode(recipient.public_key.as_bytes()),
            message: hex::encode(box_message),
            ciphertext: hex::encode(crypto_box::seal_box(box_message, &recipient.public_key)?),
        },
    })
}

fn verify(f: &Fixture) -> Result<Vec<String>> {
    if f.fixture_version != 1 || f.warning != WARNING || f.aead.len() != 4 {
        return Err("unknown or incomplete experimental fixture".into());
    }
    let mut checks = Vec::new();
    for (i, c) in f.aead.iter().enumerate() {
        let key = aead::Key::from_bytes(&bytes(&c.key)?)?;
        let nonce = aead::Nonce::try_from_slice(&bytes(&c.nonce)?)?;
        let aad = bytes(&c.aad)?;
        let message = bytes(&c.message)?;
        let ciphertext = bytes(&c.ciphertext)?;
        let prefix = format!("aead-{i}");
        check(
            aead::decrypt(&ciphertext, Some(&aad), &nonce, &key)? == message,
            &format!("{prefix}-decrypt"),
            &mut checks,
        )?;
        check(
            aead::encrypt(&message, Some(&aad), &nonce, &key)? == ciphertext,
            &format!("{prefix}-exact-ciphertext"),
            &mut checks,
        )?;
        check(
            aead::decrypt(
                &ciphertext,
                Some(&aad),
                &nonce,
                &aead::Key::from_bytes(&altered(key.as_bytes()))?,
            )
            .is_err(),
            &format!("{prefix}-wrong-key"),
            &mut checks,
        )?;
        check(
            aead::decrypt(&ciphertext, Some(&altered(&aad)), &nonce, &key).is_err(),
            &format!("{prefix}-wrong-aad"),
            &mut checks,
        )?;
        check(
            aead::decrypt(
                &ciphertext,
                Some(&aad),
                &aead::Nonce::try_from_slice(&altered(nonce.as_bytes()))?,
                &key,
            )
            .is_err(),
            &format!("{prefix}-wrong-nonce"),
            &mut checks,
        )?;
        check(
            aead::decrypt(&altered(&ciphertext), Some(&aad), &nonce, &key).is_err(),
            &format!("{prefix}-corruption"),
            &mut checks,
        )?;
        check(
            aead::decrypt(
                &ciphertext[..ciphertext.len() - 1],
                Some(&aad),
                &nonce,
                &key,
            )
            .is_err(),
            &format!("{prefix}-truncation"),
            &mut checks,
        )?;
    }
    let signer = crypto_sign::KeyPair::from_seed(&bytes(&f.sign.seed)?)?;
    let public_key = crypto_sign::PublicKey::from_bytes(&bytes(&f.sign.public_key)?)?;
    let message = bytes(&f.sign.message)?;
    let signature: [u8; 64] = bytes(&f.sign.signature)?
        .try_into()
        .map_err(|_| "bad signature length")?;
    check(
        signer.public_key == public_key,
        "ed25519-exact-public-key",
        &mut checks,
    )?;
    check(
        crypto_sign::sign_detached(&message, &signer.secret_key)? == signature,
        "ed25519-exact-signature",
        &mut checks,
    )?;
    check(
        crypto_sign::verify_detached(&signature, &message, &public_key),
        "ed25519-verify",
        &mut checks,
    )?;
    check(
        !crypto_sign::verify_detached(&signature, &altered(&message), &public_key),
        "ed25519-changed-message",
        &mut checks,
    )?;
    let bad_signature: [u8; 64] = altered(&signature).try_into().unwrap();
    check(
        !crypto_sign::verify_detached(&bad_signature, &message, &public_key),
        "ed25519-changed-signature",
        &mut checks,
    )?;
    let other_signer = crypto_sign::KeyPair::from_seed(&[0x54; 32])?;
    check(
        !crypto_sign::verify_detached(&signature, &message, &other_signer.public_key),
        "ed25519-wrong-public-key",
        &mut checks,
    )?;
    let recipient = crypto_box::KeyPair::from_seed(&bytes(&f.sealed_box.seed)?)?;
    let box_message = bytes(&f.sealed_box.message)?;
    let sealed = bytes(&f.sealed_box.ciphertext)?;
    check(
        hex::encode(recipient.public_key.as_bytes()) == f.sealed_box.public_key,
        "sealed-box-exact-public-key",
        &mut checks,
    )?;
    check(
        crypto_box::open_sealed_box(&sealed, &recipient.public_key, &recipient.secret_key)?
            == box_message,
        "sealed-box-open",
        &mut checks,
    )?;
    let other = crypto_box::KeyPair::from_seed(&[0x63; 32])?;
    check(
        crypto_box::open_sealed_box(&sealed, &other.public_key, &other.secret_key).is_err(),
        "sealed-box-wrong-recipient",
        &mut checks,
    )?;
    check(
        crypto_box::open_sealed_box(
            &altered(&sealed),
            &recipient.public_key,
            &recipient.secret_key,
        )
        .is_err(),
        "sealed-box-corruption",
        &mut checks,
    )?;
    check(
        crypto_box::open_sealed_box(
            &sealed[..sealed.len() - 1],
            &recipient.public_key,
            &recipient.secret_key,
        )
        .is_err(),
        "sealed-box-truncation",
        &mut checks,
    )?;
    Ok(checks)
}

fn peak_rss_kib() -> Option<usize> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn file_roundtrip(directory: &Path, length: usize) -> Result<serde_json::Value> {
    if length > MAX_FILE {
        return Err("file exceeds decimal 1 GB limit".into());
    }
    // The caller supplies an empty disposable directory. Never overwrite an existing file.
    if directory.exists() && fs::read_dir(directory)?.next().is_some() {
        return Err("experiment directory must be empty".into());
    }
    fs::create_dir_all(directory)?;
    let started = Instant::now();
    let baseline_rss = peak_rss_kib();
    let count = length.div_ceil(CHUNK);
    let source_path = directory.join("synthetic-source.bin");
    let mut source = File::create_new(&source_path)?;
    let mut buffer = vec![0u8; CHUNK];
    let mut remaining = length;
    while remaining != 0 {
        let part = remaining.min(CHUNK);
        random::fill_bytes(&mut buffer[..part]);
        source.write_all(&buffer[..part])?;
        remaining -= part;
    }
    source.sync_all()?;
    drop(source);
    let key = aead::Key::generate();
    let prefix = random::bytes(16);
    let mut input = File::open(&source_path)?;
    let mut input_hash = sha256::State::new();
    let mut inventory = Vec::new();
    let mut ciphertext_bytes = 0usize;
    for index in 0..count {
        let part = (length - index * CHUNK).min(CHUNK);
        input.read_exact(&mut buffer[..part])?;
        input_hash.update(&buffer[..part]);
        let mut n = [0; 24];
        n[..16].copy_from_slice(&prefix);
        n[16..].copy_from_slice(&(index as u64).to_le_bytes());
        let aad = format!("anynote/p01/file-only/{index}/{count}/{part}");
        let ciphertext = aead::encrypt(
            &buffer[..part],
            Some(aad.as_bytes()),
            &aead::Nonce::from_bytes(n),
            &key,
        )?;
        ciphertext_bytes += ciphertext.len();
        inventory.push(sha256::hash(&ciphertext));
        let mut file = File::create_new(directory.join(format!("{index}.ciphertext")))?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
    }
    let mut extra = [0];
    if input.read(&mut extra)? != 0 {
        return Err("source changed".into());
    }
    let mut output = File::create_new(directory.join("explicit-synthetic-export.bin"))?;
    let mut output_hash = sha256::State::new();
    for (index, digest) in inventory.iter().enumerate() {
        let part = (length - index * CHUNK).min(CHUNK);
        let ciphertext = fs::read(directory.join(format!("{index}.ciphertext")))?;
        if ciphertext.len() != part + 16 || &sha256::hash(&ciphertext) != digest {
            return Err("ciphertext inventory mismatch".into());
        }
        let mut n = [0; 24];
        n[..16].copy_from_slice(&prefix);
        n[16..].copy_from_slice(&(index as u64).to_le_bytes());
        let aad = format!("anynote/p01/file-only/{index}/{count}/{part}");
        let plaintext = aead::decrypt(
            &ciphertext,
            Some(aad.as_bytes()),
            &aead::Nonce::from_bytes(n),
            &key,
        )?;
        output_hash.update(&plaintext);
        output.write_all(&plaintext)?;
    }
    output.sync_all()?;
    let source_hash = input_hash.finalize();
    let recovered_hash = output_hash.finalize();
    if source_hash != recovered_hash || output.metadata()?.len() != length as u64 {
        return Err("synthetic export hash/length mismatch".into());
    }
    Ok(
        json!({"mode":"native-file-roundtrip", "plaintext_bytes":length, "chunks":count,
        "ciphertext_bytes":ciphertext_bytes, "sha256":hex::encode(source_hash),
        "elapsed_ms":started.elapsed().as_millis(), "baseline_peak_rss_kib":baseline_rss,
        "peak_rss_kib":peak_rss_kib(), "sodium_version":version::version_string(),
        "limitation":"local synthetic disk pipeline; no backend, recovery, manifest or Windows acceptance"}),
    )
}

fn run() -> Result<()> {
    ensure_init()?;
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("emit") => println!("{}", serde_json::to_string(&emit()?)?),
        Some("verify") => {
            let mut input = Vec::new();
            std::io::stdin().take(262_145).read_to_end(&mut input)?;
            if input.len() > 262_144 {
                return Err("fixture too large".into());
            }
            let fixture: Fixture = serde_json::from_slice(&input)?;
            let checks = verify(&fixture)?;
            println!(
                "{}",
                json!({"status":"PASS","checks":checks,"sodium_version":version::version_string()})
            );
        }
        Some("kdf") if args.len() == 2 => {
            let mut input = Vec::new();
            std::io::stdin().take(4097).read_to_end(&mut input)?;
            if input.len() > 4096 {
                return Err("KDF input too large".into());
            }
            let request: kdf::Request = serde_json::from_slice(&input)?;
            println!("{}", request.derive()?);
        }
        Some("file-roundtrip") if args.len() == 4 => {
            println!("{}", file_roundtrip(Path::new(&args[2]), args[3].parse()?)?);
        }
        _ => return Err(
            "usage: anynote-p01 emit | verify (stdin JSON) | file-roundtrip EMPTY_DIRECTORY BYTES"
                .into(),
        ),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("P01 experiment failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_primitive_positive_and_negative_checks_execute() {
        ensure_init().unwrap();
        assert_eq!(verify(&emit().unwrap()).unwrap().len(), 39);
    }
    #[test]
    fn changed_fixture_ciphertext_is_not_accepted() {
        ensure_init().unwrap();
        let mut f = emit().unwrap();
        f.aead[0].ciphertext = hex::encode(altered(&bytes(&f.aead[0].ciphertext).unwrap()));
        assert!(verify(&f).is_err());
    }
    #[test]
    fn oversize_is_rejected_before_directory_creation() {
        assert!(
            file_roundtrip(Path::new("/must-not-be-created-anynote-p01"), MAX_FILE + 1).is_err()
        );
    }
}
