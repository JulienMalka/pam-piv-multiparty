//! PIV via PKCS#11. Loads a PKCS#11 module (typically
//! `opensc-pkcs11.so`) at runtime; reads the slot-9a public key and
//! signs challenges via standard Cryptoki calls.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::RawAuthPin;
use p256::pkcs8::EncodePublicKey;
use std::path::Path;
use thiserror::Error;

const PIV_AUTH_KEY_ID: &[u8] = &[0x01];
const SEC1_P256_LEN: usize = 65;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("loading PKCS#11 module `{path}`: {source}")]
    LoadModule {
        path: String,
        #[source]
        source: Pkcs11Error,
    },
    #[error("PKCS#11: {0}")]
    Pkcs11(#[from] Pkcs11Error),
    #[error("no PIV-capable tokens present")]
    NoDevices,
    #[error("on token `{token}` ({op}): {source}")]
    Op {
        token: String,
        op: &'static str,
        #[source]
        source: Pkcs11Error,
    },
    #[error("on token `{token}`: slot-9a object missing")]
    SlotEmpty { token: String },
    #[error("on token `{token}`: invalid slot-9a public key")]
    InvalidPublicKey { token: String },
    #[error("on token `{token}`: PIN locked")]
    PinLocked { token: String },
    #[error("on token `{token}`: PIN incorrect")]
    PinIncorrect { token: String },
}

#[derive(Debug, Clone)]
pub struct DeviceHandle {
    slot: Slot,
    pub token_label: String,
}

pub struct Pkcs11Backend {
    pkcs11: Pkcs11,
}

impl Pkcs11Backend {
    pub fn new(module_path: &Path) -> Result<Self, BackendError> {
        let pkcs11 = Pkcs11::new(module_path).map_err(|source| BackendError::LoadModule {
            path: module_path.display().to_string(),
            source,
        })?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
        Ok(Self { pkcs11 })
    }

    pub fn enumerate(&self) -> Result<Vec<DeviceHandle>, BackendError> {
        let slots = self.pkcs11.get_slots_with_token()?;
        if slots.is_empty() {
            return Err(BackendError::NoDevices);
        }
        slots
            .into_iter()
            .map(|slot| {
                let label = self
                    .pkcs11
                    .get_token_info(slot)
                    .map(|i| i.label().trim().to_string())
                    .unwrap_or_else(|_| format!("slot {}", slot.id()));
                Ok(DeviceHandle {
                    slot,
                    token_label: label,
                })
            })
            .collect()
    }

    pub fn read_slot9a_spki(&self, device: &DeviceHandle) -> Result<Vec<u8>, BackendError> {
        let session = self.open_ro(device)?;
        let template = [
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(PIV_AUTH_KEY_ID.to_vec()),
        ];
        let mut handles = session
            .find_objects(&template)
            .map_err(|e| op_err(device, "find slot-9a public key", e))?;
        let handle = handles.pop().ok_or_else(|| BackendError::SlotEmpty {
            token: device.token_label.clone(),
        })?;
        let attrs = session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .map_err(|e| op_err(device, "read slot-9a EC point", e))?;
        let ec_point = match attrs.into_iter().next() {
            Some(Attribute::EcPoint(v)) => v,
            _ => {
                return Err(BackendError::InvalidPublicKey {
                    token: device.token_label.clone(),
                })
            }
        };
        let raw = unwrap_p256_point(&ec_point).ok_or_else(|| BackendError::InvalidPublicKey {
            token: device.token_label.clone(),
        })?;
        let pk =
            p256::PublicKey::from_sec1_bytes(raw).map_err(|_| BackendError::InvalidPublicKey {
                token: device.token_label.clone(),
            })?;
        pk.to_public_key_der()
            .map(|d| d.as_bytes().to_vec())
            .map_err(|_| BackendError::InvalidPublicKey {
                token: device.token_label.clone(),
            })
    }

    pub fn verify_pin_and_sign(
        &self,
        device: &DeviceHandle,
        pin: &[u8],
        challenge: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        let session = self.open_ro(device)?;
        let raw_pin = RawAuthPin::new(Box::new(pin.to_vec()));
        session
            .login_with_raw(UserType::User, &raw_pin)
            .map_err(|e| classify_login_err(&device.token_label, e))?;

        let key_template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(PIV_AUTH_KEY_ID.to_vec()),
        ];
        let mut keys = session
            .find_objects(&key_template)
            .map_err(|e| op_err(device, "find slot-9a private key", e))?;
        let key = keys.pop().ok_or_else(|| BackendError::SlotEmpty {
            token: device.token_label.clone(),
        })?;

        session
            .sign(&Mechanism::EcdsaSha256, key, challenge)
            .map_err(|e| op_err(device, "sign", e))
    }

    fn open_ro(&self, device: &DeviceHandle) -> Result<Session, BackendError> {
        self.pkcs11
            .open_ro_session(device.slot)
            .map_err(|e| op_err(device, "open session", e))
    }
}

fn unwrap_p256_point(value: &[u8]) -> Option<&[u8]> {
    match value.len() {
        // DER OCTET STRING: 04 (tag) | 41 (len = 65) | <65 bytes SEC1>
        n if n == SEC1_P256_LEN + 2 && value[0] == 0x04 && value[1] == 0x41 => Some(&value[2..]),
        // Bare SEC1 uncompressed point.
        n if n == SEC1_P256_LEN && value[0] == 0x04 => Some(value),
        _ => None,
    }
}

fn op_err(device: &DeviceHandle, op: &'static str, source: Pkcs11Error) -> BackendError {
    BackendError::Op {
        token: device.token_label.clone(),
        op,
        source,
    }
}

fn classify_login_err(token: &str, err: Pkcs11Error) -> BackendError {
    match err {
        Pkcs11Error::Pkcs11(RvError::PinIncorrect, _) => BackendError::PinIncorrect {
            token: token.to_string(),
        },
        Pkcs11Error::Pkcs11(RvError::PinLocked, _) => BackendError::PinLocked {
            token: token.to_string(),
        },
        other => BackendError::Op {
            token: token.to_string(),
            op: "login",
            source: other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwraps_octet_string_form() {
        let mut wrapped = vec![0x04, 0x41, 0x04];
        wrapped.extend(vec![0x11; 64]);
        let raw = unwrap_p256_point(&wrapped).unwrap();
        assert_eq!(raw.len(), 65);
        assert_eq!(raw[0], 0x04);
    }

    #[test]
    fn accepts_bare_sec1() {
        let mut bare = vec![0x04];
        bare.extend(vec![0x22; 64]);
        let raw = unwrap_p256_point(&bare).unwrap();
        assert_eq!(raw.len(), 65);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(unwrap_p256_point(&[0x04, 0x41]).is_none());
        assert!(unwrap_p256_point(&[0x04; 100]).is_none());
    }

    #[test]
    fn rejects_compressed_point() {
        let mut compressed = vec![0x02];
        compressed.extend(vec![0x33; 32]);
        assert!(unwrap_p256_point(&compressed).is_none());
    }
}
