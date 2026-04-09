use crate::authfile::Entry;
use crate::backend::{BackendError, Pkcs11Backend};
use crate::config::ModuleConfig;
use crate::conv::{expand_cue, log_info, prompt_pin, send_info, ConvError};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use pam::module::PamHandle;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("no credentials registered for group `{0}`")]
    NoCredentialsForGroup(String),
    #[error(
        "group `{group}`: no device present whose slot-9a public key is registered for this group{}",
        format_skipped(.skipped)
    )]
    NoMatchingDevice {
        group: String,
        skipped: Vec<(String, String)>,
    },
    #[error("group `{group}`: {source}")]
    Backend {
        group: String,
        #[source]
        source: BackendError,
    },
    #[error("group `{group}`: PIN incorrect")]
    PinIncorrect { group: String },
    #[error("group `{group}`: PIN locked")]
    PinLocked { group: String },
    #[error("group `{group}`: conversation error: {source}")]
    Conv {
        group: String,
        #[source]
        source: ConvError,
    },
    #[error("group `{group}`: challenge signature did not verify against slot-9a key")]
    SignatureInvalid { group: String },
}

pub fn user_facing(err: &PolicyError) -> String {
    match err {
        PolicyError::NoCredentialsForGroup(g) => {
            format!("Not enrolled for group `{g}`.")
        }
        PolicyError::NoMatchingDevice { group, .. } => {
            format!("No registered device present for group `{group}`.")
        }
        PolicyError::PinLocked { .. } => "Card PIN is locked. Contact your administrator.".into(),
        PolicyError::PinIncorrect { .. } => "Wrong PIN.".into(),
        PolicyError::Backend { .. }
        | PolicyError::Conv { .. }
        | PolicyError::SignatureInvalid { .. } => "Authentication failed.".into(),
    }
}

pub fn authenticate(
    pamh: &mut PamHandle,
    cfg: &ModuleConfig,
    entries: &[Entry],
    backend: &Pkcs11Backend,
) -> Result<(), PolicyError> {
    for group in &cfg.groups {
        if !entries.iter().any(|e| &e.group == group) {
            return Err(PolicyError::NoCredentialsForGroup(group.clone()));
        }
    }

    // SPKI byte-equality identifies the physical card: slot 9a holds
    // one non-exportable key pair, so duplicate SPKI ⇒ same device.
    let mut used: HashSet<Vec<u8>> = HashSet::new();

    for group in &cfg.groups {
        run_group(pamh, group, cfg, entries, backend, &mut used)?;
    }

    Ok(())
}

fn run_group(
    pamh: &mut PamHandle,
    group: &str,
    cfg: &ModuleConfig,
    entries: &[Entry],
    backend: &Pkcs11Backend,
    used: &mut HashSet<Vec<u8>>,
) -> Result<(), PolicyError> {
    let group_spkis: Vec<&[u8]> = entries
        .iter()
        .filter(|e| e.group == group)
        .map(|e| e.spki_der.as_slice())
        .collect();

    send_info(pamh, &expand_cue(&cfg.cue_prompt, group));

    let devices = backend.enumerate().map_err(|source| PolicyError::Backend {
        group: group.to_string(),
        source,
    })?;

    let mut skipped: Vec<(String, String)> = Vec::new();
    for device in &devices {
        let spki = match backend.read_slot9a_spki(device) {
            Ok(s) => s,
            Err(e) => {
                skipped.push((device.token_label.clone(), e.to_string()));
                continue;
            }
        };
        if used.contains(&spki) {
            continue;
        }
        if !group_spkis.contains(&spki.as_slice()) {
            continue;
        }

        let prompt = format!("PIN for YubiKey in group {}: ", group);
        let pin = prompt_pin(pamh, &prompt).map_err(|source| PolicyError::Conv {
            group: group.to_string(),
            source,
        })?;

        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);

        let signature = backend
            .verify_pin_and_sign(device, &pin, &challenge)
            .map_err(|source| classify_backend_err(group, source))?;

        verify_challenge_signature(&spki, &challenge, &signature).map_err(|_| {
            PolicyError::SignatureInvalid {
                group: group.to_string(),
            }
        })?;

        let fp = Sha256::digest(&spki);
        log_info(
            pamh,
            &format!(
                "pam_piv_multiparty: group=`{}` approved by spki-fp={}",
                group,
                hex::encode(&fp[..8])
            ),
        );

        used.insert(spki);
        return Ok(());
    }

    Err(PolicyError::NoMatchingDevice {
        group: group.to_string(),
        skipped,
    })
}

fn classify_backend_err(group: &str, source: BackendError) -> PolicyError {
    match source {
        BackendError::PinLocked { .. } => PolicyError::PinLocked {
            group: group.to_string(),
        },
        BackendError::PinIncorrect { .. } => PolicyError::PinIncorrect {
            group: group.to_string(),
        },
        other => PolicyError::Backend {
            group: group.to_string(),
            source: other,
        },
    }
}

fn format_skipped(skipped: &[(String, String)]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = skipped.iter().map(|(r, e)| format!("[{r}: {e}]")).collect();
    format!(" (readers skipped due to errors: {})", parts.join(" "))
}

fn verify_challenge_signature(
    spki_der: &[u8],
    challenge: &[u8],
    signature_raw: &[u8],
) -> Result<(), ()> {
    let vk_res = VerifyingKey::from_public_key_der(spki_der);
    let sig_res = Signature::from_slice(signature_raw);
    match (vk_res, sig_res) {
        (Ok(vk), Ok(sig)) => vk.verify(challenge, &sig).map_err(|_| ()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::pkcs8::EncodePublicKey;

    fn make_spki() -> (Vec<u8>, SigningKey) {
        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let spki = sk
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        (spki, sk)
    }

    #[test]
    fn challenge_verifier_accepts_real_signature() {
        let (spki, sk) = make_spki();
        let challenge = [0x42u8; 32];
        let sig: Signature = sk.sign(&challenge);
        verify_challenge_signature(&spki, &challenge, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn challenge_verifier_rejects_wrong_challenge() {
        let (spki, sk) = make_spki();
        let sig: Signature = sk.sign(b"a different challenge");
        verify_challenge_signature(&spki, &[0x42u8; 32], &sig.to_bytes()).unwrap_err();
    }

    #[test]
    fn challenge_verifier_rejects_wrong_key() {
        let (_, sk) = make_spki();
        let (other_spki, _) = make_spki();
        let challenge = [0x42u8; 32];
        let sig: Signature = sk.sign(&challenge);
        verify_challenge_signature(&other_spki, &challenge, &sig.to_bytes()).unwrap_err();
    }
}
