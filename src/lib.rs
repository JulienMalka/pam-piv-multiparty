//! piv-multiparty: PIV-based PAM module enforcing multi-party
//! authentication with cryptographic per-device identity.

use pam::constants::{PamFlag, PamResultCode};
use pam::items::User;
use pam::module::{PamHandle, PamHooks};
use std::ffi::CStr;

#[doc(hidden)]
pub mod authfile;
mod backend;
mod config;
mod conv;
mod policy;

struct PamMultiparty;

pam::pam_hooks!(PamMultiparty);

impl PamHooks for PamMultiparty {
    fn sm_authenticate(
        pamh: &mut PamHandle,
        args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        let cfg = match config::ModuleConfig::parse(&args) {
            Ok(c) => c,
            Err(e) => {
                conv::log_error(pamh, &format!("pam_piv_multiparty: invalid args: {e}"));
                conv::send_error_to_user(pamh, "Authentication unavailable.");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        if cfg.debug {
            conv::log_debug(
                pamh,
                &format!("pam_piv_multiparty: start groups={:?}", cfg.groups),
            );
        }

        // pam-bindings 0.1's `get_user` has a broken FFI declaration
        // (user: &*mut c_char instead of *mut *mut c_char) that loses
        // the written-back pointer; it returns Err(PAM_SUCCESS) even on
        // a successful underlying call. Read the PAM_USER item directly.
        let user: String = match pamh.get_item::<User>() {
            Ok(Some(u)) => u.0.to_string_lossy().into_owned(),
            Ok(None) => {
                conv::log_error(pamh, "pam_piv_multiparty: PAM_USER not set");
                conv::send_error_to_user(pamh, "Authentication failed.");
                return PamResultCode::PAM_USER_UNKNOWN;
            }
            Err(code) => {
                conv::log_error(pamh, &format!("pam_piv_multiparty: get_item(User) err {code:?}"));
                conv::send_error_to_user(pamh, "Authentication failed.");
                return code;
            }
        };

        let entries = match authfile::load_for_user(&cfg.authfile, &user) {
            Ok(e) => e,
            Err(e) => {
                conv::log_error(
                    pamh,
                    &format!("pam_piv_multiparty: reading authfile for {user}: {e}"),
                );
                conv::send_error_to_user(pamh, "Authentication failed.");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        let backend = match backend::Pkcs11Backend::new(&cfg.pkcs11_module) {
            Ok(b) => b,
            Err(e) => {
                conv::log_error(pamh, &format!("pam_piv_multiparty: PKCS#11 init failed: {e}"));
                conv::send_error_to_user(pamh, "Authentication failed.");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        match policy::authenticate(pamh, &cfg, &entries, &backend) {
            Ok(()) => PamResultCode::PAM_SUCCESS,
            Err(e) => {
                // Full error to syslog; curated subset to the user.
                conv::log_error(pamh, &format!("pam_piv_multiparty: auth failed: {e}"));
                conv::send_error_to_user(pamh, &policy::user_facing(&e));
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    fn sm_setcred(
        _pamh: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(
        _pamh: &mut PamHandle,
        _args: Vec<&CStr>,
        _flags: PamFlag,
    ) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}
