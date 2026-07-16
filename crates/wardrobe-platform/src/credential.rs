use wardrobe_core::{
    CredentialLocator, CredentialPort, PortError, PortErrorKind, PortResult, SecretString,
};

pub const KEYCHAIN_SERVICE: &str = "com.devrai.wardrobe.credentials";

#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsKeychain;

impl MacOsKeychain {
    #[cfg(target_os = "macos")]
    pub fn get_exact(&self, locator: &CredentialLocator) -> PortResult<SecretString> {
        use security_framework_sys::base::errSecItemNotFound;

        let mut bytes = match security_framework::passwords::get_generic_password(
            KEYCHAIN_SERVICE,
            locator.expose_locator(),
        ) {
            Ok(bytes) => bytes,
            Err(error) if error.code() == errSecItemNotFound => {
                return Err(PortError::new(PortErrorKind::NotFound))
            }
            Err(error) => return Err(map_keychain_error(error)),
        };
        let result = std::str::from_utf8(&bytes)
            .map(|value| SecretString::new(value.to_owned()))
            .map_err(|_| PortError::new(PortErrorKind::DataIntegrity));
        bytes.fill(0);
        result
    }

    #[cfg(not(target_os = "macos"))]
    pub fn get_exact(&self, _locator: &CredentialLocator) -> PortResult<SecretString> {
        Err(PortError::new(PortErrorKind::Unavailable))
    }
}

#[cfg(target_os = "macos")]
impl CredentialPort for MacOsKeychain {
    fn put(&self, locator: &CredentialLocator, secret: &SecretString) -> PortResult<()> {
        security_framework::passwords::set_generic_password(
            KEYCHAIN_SERVICE,
            locator.expose_locator(),
            secret.expose_secret().as_bytes(),
        )
        .map_err(map_keychain_error)
    }

    fn get(&self, locator: &CredentialLocator) -> PortResult<SecretString> {
        self.get_exact(locator)
    }

    fn contains(&self, locator: &CredentialLocator) -> PortResult<bool> {
        use security_framework_sys::base::errSecItemNotFound;

        match security_framework::passwords::get_generic_password(
            KEYCHAIN_SERVICE,
            locator.expose_locator(),
        ) {
            Ok(mut secret) => {
                secret.fill(0);
                Ok(true)
            }
            Err(error) if error.code() == errSecItemNotFound => Ok(false),
            Err(error) => Err(map_keychain_error(error)),
        }
    }

    fn delete(&self, locator: &CredentialLocator) -> PortResult<()> {
        use security_framework_sys::base::errSecItemNotFound;

        match security_framework::passwords::delete_generic_password(
            KEYCHAIN_SERVICE,
            locator.expose_locator(),
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == errSecItemNotFound => Ok(()),
            Err(error) => Err(map_keychain_error(error)),
        }
    }
}

#[cfg(target_os = "macos")]
fn map_keychain_error(error: security_framework::base::Error) -> PortError {
    const ERR_SEC_AUTH_FAILED: i32 = security_framework_sys::base::errSecAuthFailed;
    const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

    let kind = match error.code() {
        ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => PortErrorKind::PermissionDenied,
        ERR_SEC_NOT_AVAILABLE => PortErrorKind::Unavailable,
        _ => PortErrorKind::Internal,
    };
    PortError::new(kind)
}

#[cfg(not(target_os = "macos"))]
impl CredentialPort for MacOsKeychain {
    fn put(&self, _locator: &CredentialLocator, _secret: &SecretString) -> PortResult<()> {
        Err(PortError::new(PortErrorKind::Unavailable))
    }

    fn get(&self, locator: &CredentialLocator) -> PortResult<SecretString> {
        self.get_exact(locator)
    }

    fn contains(&self, _locator: &CredentialLocator) -> PortResult<bool> {
        Err(PortError::new(PortErrorKind::Unavailable))
    }

    fn delete(&self, _locator: &CredentialLocator) -> PortResult<()> {
        Err(PortError::new(PortErrorKind::Unavailable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    #[ignore = "requires P01_LIVE_KEYCHAIN=1 and an unlocked login Keychain"]
    fn real_keychain_round_trip() {
        if std::env::var("P01_LIVE_KEYCHAIN").as_deref() != Ok("1") {
            return;
        }
        let locator = CredentialLocator::new(format!("p01-live-{}", Uuid::new_v4())).unwrap();
        let keychain = MacOsKeychain;
        let secret = SecretString::new(format!("p01-secret-{}", Uuid::new_v4()));
        keychain.put(&locator, &secret).unwrap();
        assert!(keychain.contains(&locator).unwrap());
        assert_eq!(
            keychain.get_exact(&locator).unwrap().expose_secret(),
            secret.expose_secret()
        );
        keychain.delete(&locator).unwrap();
        assert!(!keychain.contains(&locator).unwrap());
    }
}
