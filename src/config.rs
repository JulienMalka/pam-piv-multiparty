use std::ffi::CStr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required module argument: {0}")]
    MissingArg(&'static str),
    #[error("invalid utf-8 in module argument")]
    NotUtf8,
    #[error("empty groups list")]
    EmptyGroups,
    #[error("duplicate group name: {0}")]
    DuplicateGroup(String),
    #[error("unknown module argument: {0}")]
    UnknownArg(String),
}

#[derive(Debug, Clone)]
pub struct ModuleConfig {
    pub authfile: PathBuf,
    pub groups: Vec<String>,
    pub pkcs11_module: PathBuf,
    pub cue_prompt: String,
    pub debug: bool,
}

impl ModuleConfig {
    pub fn parse(args: &[&CStr]) -> Result<Self, ConfigError> {
        let mut authfile: Option<PathBuf> = None;
        let mut groups: Option<Vec<String>> = None;
        let mut pkcs11_module: Option<PathBuf> = None;
        let mut cue_prompt: String = "Present YubiKey for group %g".to_string();
        let mut debug = false;

        for arg in args {
            let s = arg.to_str().map_err(|_| ConfigError::NotUtf8)?;
            if let Some((k, v)) = s.split_once('=') {
                match k {
                    "authfile" => authfile = Some(PathBuf::from(v)),
                    "groups" => {
                        groups = Some(
                            v.split(',')
                                .map(|g| g.trim().to_string())
                                .filter(|g| !g.is_empty())
                                .collect(),
                        )
                    }
                    "pkcs11_module" => pkcs11_module = Some(PathBuf::from(v)),
                    "cue_prompt" => cue_prompt = v.to_string(),
                    other => return Err(ConfigError::UnknownArg(other.to_string())),
                }
            } else if s == "debug" {
                debug = true;
            } else {
                return Err(ConfigError::UnknownArg(s.to_string()));
            }
        }

        let authfile = authfile.ok_or(ConfigError::MissingArg("authfile"))?;
        let groups = groups.ok_or(ConfigError::MissingArg("groups"))?;
        let pkcs11_module = pkcs11_module.ok_or(ConfigError::MissingArg("pkcs11_module"))?;

        if groups.is_empty() {
            return Err(ConfigError::EmptyGroups);
        }

        let mut seen = std::collections::HashSet::new();
        for g in &groups {
            if !seen.insert(g.clone()) {
                return Err(ConfigError::DuplicateGroup(g.clone()));
            }
        }

        Ok(Self {
            authfile,
            groups,
            pkcs11_module,
            cue_prompt,
            debug,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cstrs(args: &[&str]) -> Vec<CString> {
        args.iter().map(|s| CString::new(*s).unwrap()).collect()
    }

    fn cstr_refs(cs: &[CString]) -> Vec<&CStr> {
        cs.iter().map(|c| c.as_c_str()).collect()
    }

    const PKCS11: &str = "pkcs11_module=/run/current-system/sw/lib/opensc-pkcs11.so";

    #[test]
    fn parses_minimal_args() {
        let owned = cstrs(&[
            "authfile=/var/lib/piv-multiparty/user.map",
            "groups=A,B",
            PKCS11,
        ]);
        let args = cstr_refs(&owned);
        let cfg = ModuleConfig::parse(&args).unwrap();
        assert_eq!(cfg.authfile, PathBuf::from("/var/lib/piv-multiparty/user.map"));
        assert_eq!(cfg.groups, vec!["A", "B"]);
        assert!(!cfg.debug);
    }

    #[test]
    fn missing_authfile_errors() {
        let owned = cstrs(&["groups=A,B", PKCS11]);
        let args = cstr_refs(&owned);
        let err = ModuleConfig::parse(&args).unwrap_err();
        assert!(matches!(err, ConfigError::MissingArg("authfile")));
    }

    #[test]
    fn missing_pkcs11_module_errors() {
        let owned = cstrs(&["authfile=/tmp/x", "groups=A"]);
        let args = cstr_refs(&owned);
        let err = ModuleConfig::parse(&args).unwrap_err();
        assert!(matches!(err, ConfigError::MissingArg("pkcs11_module")));
    }

    #[test]
    fn duplicate_group_rejected() {
        let owned = cstrs(&["authfile=/tmp/x", "groups=A,B,A", PKCS11]);
        let args = cstr_refs(&owned);
        let err = ModuleConfig::parse(&args).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateGroup(ref g) if g == "A"));
    }

    #[test]
    fn debug_flag_parsed() {
        let owned = cstrs(&["authfile=/tmp/x", "groups=A", PKCS11, "debug"]);
        let args = cstr_refs(&owned);
        let cfg = ModuleConfig::parse(&args).unwrap();
        assert!(cfg.debug);
    }

    #[test]
    fn unknown_kv_arg_rejected() {
        let owned = cstrs(&["authfile=/tmp/x", "groups=A", PKCS11, "fnord=bar"]);
        let args = cstr_refs(&owned);
        let err = ModuleConfig::parse(&args).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownArg(ref a) if a == "fnord"));
    }

    #[test]
    fn unknown_bare_arg_rejected() {
        let owned = cstrs(&["authfile=/tmp/x", "groups=A", PKCS11, "verbose"]);
        let args = cstr_refs(&owned);
        let err = ModuleConfig::parse(&args).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownArg(ref a) if a == "verbose"));
    }

    #[test]
    fn empty_groups_list_rejected() {
        let owned = cstrs(&["authfile=/tmp/x", "groups=", PKCS11]);
        let args = cstr_refs(&owned);
        let err = ModuleConfig::parse(&args).unwrap_err();
        assert!(matches!(err, ConfigError::EmptyGroups));
    }
}
