//! Thin helpers around the PAM conversation and syslog.

use log::LevelFilter;
use pam::constants::PAM_PROMPT_ECHO_OFF;
use pam::conv::Conv;
use pam::module::PamHandle;
use std::sync::OnceLock;
use syslog::{BasicLogger, Facility, Formatter3164};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum ConvError {
    #[error("PAM conversation item unavailable")]
    NoConv,
    #[error("PAM conversation failed: {0:?}")]
    ConvFailed(pam::constants::PamResultCode),
    #[error("user cancelled the prompt")]
    Cancelled,
}

/// Prompt for a PIN; zeroises the returned bytes on drop.
pub fn prompt_pin(pamh: &mut PamHandle, prompt: &str) -> Result<Zeroizing<Vec<u8>>, ConvError> {
    let conv = pamh
        .get_item::<Conv>()
        .map_err(ConvError::ConvFailed)?
        .ok_or(ConvError::NoConv)?;
    let resp = conv
        .send(PAM_PROMPT_ECHO_OFF, prompt)
        .map_err(ConvError::ConvFailed)?;
    let bytes = match resp {
        Some(c) => c.to_bytes().to_vec(),
        None => return Err(ConvError::Cancelled),
    };
    Ok(Zeroizing::new(bytes))
}

/// Best-effort PAM_TEXT_INFO message; failures are not fatal.
pub fn send_info(pamh: &mut PamHandle, text: &str) {
    use pam::constants::PAM_TEXT_INFO;
    if let Ok(Some(conv)) = pamh.get_item::<Conv>() {
        let _ = conv.send(PAM_TEXT_INFO, text);
    }
}

/// Best-effort PAM_ERROR_MSG. Never echo internal error detail here.
pub fn send_error_to_user(pamh: &mut PamHandle, text: &str) {
    use pam::constants::PAM_ERROR_MSG;
    if let Ok(Some(conv)) = pamh.get_item::<Conv>() {
        let _ = conv.send(PAM_ERROR_MSG, text);
    }
}

pub fn log_error(_pamh: &PamHandle, msg: &str) {
    init_syslog_once();
    log::log!(log::Level::Error, "{msg}");
}

pub fn log_info(_pamh: &PamHandle, msg: &str) {
    init_syslog_once();
    log::log!(log::Level::Info, "{msg}");
}

pub fn log_debug(_pamh: &PamHandle, msg: &str) {
    init_syslog_once();
    log::log!(log::Level::Debug, "{msg}");
}

fn init_syslog_once() {
    static LOGGER: OnceLock<()> = OnceLock::new();
    LOGGER.get_or_init(|| {
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "pam_piv_multiparty".into(),
            pid: std::process::id(),
        };
        if let Ok(writer) = syslog::unix(formatter) {
            let _ = log::set_boxed_logger(Box::new(BasicLogger::new(writer)));
            log::set_max_level(LevelFilter::Debug);
        }
    });
}

pub fn expand_cue(template: &str, group: &str) -> String {
    template.replace("%g", group)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_group_placeholder() {
        assert_eq!(
            expand_cue("Touch key for group %g", "A"),
            "Touch key for group A"
        );
    }

    #[test]
    fn leaves_template_without_placeholder_alone() {
        assert_eq!(expand_cue("Touch key", "A"), "Touch key");
    }

    #[test]
    fn replaces_all_occurrences() {
        assert_eq!(expand_cue("%g/%g", "X"), "X/X");
    }
}
