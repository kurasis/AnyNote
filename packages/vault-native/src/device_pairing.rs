//! Frozen P02 secretstream QR channel. Keys are native-owned and discarded at lock.
use super::*;
use libsodium_rs::crypto_secretstream::xchacha20poly1305 as stream;
use std::collections::BTreeSet;
pub(crate) struct Channel {
    key: Zeroizing<Vec<u8>>,
    new_device: bool,
    generation: u64,
    sent: BTreeSet<String>,
    received: BTreeSet<String>,
}
fn payload(message: &str) -> Result<&'static str> {
    match message {
        "new-device-offer" => Ok("offer"),
        "approver-response" => Ok("response"),
        "approver-approval" => Ok("approval"),
        "new-device-confirmation" => Ok("confirmation"),
        _ => Err(Error("UNSUPPORTED_PURPOSE")),
    }
}
fn context(codec: &Codec, message: &str, anchor: &str) -> Result<Value> {
    let value = json!({"purpose":"pairing-channel-frame","contract":"p02-state-c1","protocol":"anynote","protocol_version":1,"message":message,"anchor_digest":anchor});
    codec.validate("p02-state-c1", "channel-context", &value)?;
    Ok(value)
}
fn aad(context: &Value) -> Result<Vec<u8>> {
    let mut bytes = b"AnyNote/p02-state-c1/aad/pairing-channel-frame\0".to_vec();
    bytes.extend(canonical(context)?);
    Ok(bytes)
}
impl Channel {
    pub fn from_qr(codec: &Codec, qr: &Value, new_device: bool, generation: u64) -> Result<Self> {
        codec.validate("p02-state-c1", "qr", qr)?;
        let key = Zeroizing::new(un64(text(&qr["channel_key"])?)?);
        check(key.len() == 32, "INVALID_KEY_LENGTH")?;
        Ok(Self {
            key,
            new_device,
            generation,
            sent: BTreeSet::new(),
            received: BTreeSet::new(),
        })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn seal(
        &mut self,
        codec: &Codec,
        message: &str,
        value: &Value,
        anchor: &str,
    ) -> Result<Value> {
        let kind = payload(message)?;
        check(
            self.new_device == message.starts_with("new-device-") && !self.sent.contains(message),
            "CHANNEL_REFLECTION_OR_REPLAY",
        )?;
        codec.validate("p02-state-c1", kind, value)?;
        let plain = Zeroizing::new(canonical(value)?);
        check(plain.len() <= 16367, "RESOURCE_LIMIT")?;
        let context = context(codec, message, anchor)?;
        let key = stream::Key::from_bytes(&self.key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        let (mut state, header) =
            stream::PushState::init_push(&key).map_err(|_| Error("CRYPTO_FAILURE"))?;
        let cipher = state
            .push(&plain, Some(&aad(&context)?), stream::TAG_FINAL)
            .map_err(|_| Error("CRYPTO_FAILURE"))?;
        let frame = json!({"context":context,"header":b64(&header),"ciphertext":b64(&cipher)});
        codec.validate("p02-state-c1", "frame", &frame)?;
        self.sent.insert(message.into());
        Ok(frame)
    }
    pub fn open(
        &mut self,
        codec: &Codec,
        frame: &Value,
        message: &str,
        anchor: &str,
    ) -> Result<Value> {
        let kind = payload(message)?;
        check(
            self.new_device != message.starts_with("new-device-")
                && !self.received.contains(message),
            "CHANNEL_REFLECTION_OR_REPLAY",
        )?;
        codec.validate("p02-state-c1", "frame", frame)?;
        let expected = context(codec, message, anchor)?;
        check(frame["context"] == expected, "CHANNEL_CONTEXT_MISMATCH")?;
        let header: [u8; 24] = un64(text(&frame["header"])?)?
            .try_into()
            .map_err(|_| Error("INVALID_NONCE"))?;
        let key = stream::Key::from_bytes(&self.key).map_err(|_| Error("INVALID_KEY_LENGTH"))?;
        let mut state = stream::PullState::init_pull(&header, &key)
            .map_err(|_| Error("CHANNEL_INTEGRITY_FAILURE"))?;
        let (plain, tag) = state
            .pull(&un64(text(&frame["ciphertext"])?)?, Some(&aad(&expected)?))
            .map_err(|_| Error("CHANNEL_INTEGRITY_FAILURE"))?;
        let plain = Zeroizing::new(plain);
        check(tag == stream::TAG_FINAL, "CHANNEL_INTEGRITY_FAILURE")?;
        let value = codec.decode("p02-state-c1", kind, &plain)?;
        self.received.insert(message.into());
        Ok(value)
    }
}
