use crate::{PhotoKitKeyError, PhotoKitKeyPort, PhotoKitRootKey};

pub const PHOTOKIT_KEYCHAIN_SERVICE: &str = "com.devrai.wardrobe.photokit.locator.v1";

#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsPhotoKitKeychain;

#[cfg(target_os = "macos")]
impl PhotoKitKeyPort for MacOsPhotoKitKeychain {
    fn create_root_key(&self, key_reference: &str) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        use security_framework::passwords::{
            set_generic_password_options, AccessControlOptions, PasswordOptions,
        };

        validate_key_reference(key_reference)?;
        let root_key = PhotoKitRootKey::generate()?;
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlock),
            AccessControlOptions::empty().bits(),
        )
        .map_err(map_keychain_error)?;
        let mut options =
            PasswordOptions::new_generic_password(PHOTOKIT_KEYCHAIN_SERVICE, key_reference);
        options.set_access_synchronized(Some(false));
        options.set_access_control(access_control);
        set_generic_password_options(root_key.expose(), options).map_err(map_keychain_error)?;
        Ok(root_key)
    }

    fn load_root_key(
        &self,
        key_reference: &str,
        allow_authentication_ui: bool,
    ) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
        use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};

        validate_key_reference(key_reference)?;
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::generic_password())
            .service(PHOTOKIT_KEYCHAIN_SERVICE)
            .account(key_reference)
            .cloud_sync(Some(false))
            .load_data(true)
            .limit(1)
            .skip_authenticated_items(!allow_authentication_ui);
        let mut results = query.search().map_err(map_keychain_error)?;
        if results.len() != 1 {
            return Err(PhotoKitKeyError::Integrity);
        }
        let SearchResult::Data(mut bytes) = results.remove(0) else {
            return Err(PhotoKitKeyError::Integrity);
        };
        if bytes.len() != 32 {
            bytes.fill(0);
            return Err(PhotoKitKeyError::Integrity);
        }
        let mut root = [0_u8; 32];
        root.copy_from_slice(&bytes);
        bytes.fill(0);
        Ok(PhotoKitRootKey::from_bytes(root))
    }

    fn delete_root_key(&self, key_reference: &str) -> Result<(), PhotoKitKeyError> {
        use security_framework::item::{ItemClass, ItemSearchOptions};
        use security_framework_sys::base::errSecItemNotFound;

        validate_key_reference(key_reference)?;
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::generic_password())
            .service(PHOTOKIT_KEYCHAIN_SERVICE)
            .account(key_reference)
            .cloud_sync(Some(false))
            .skip_authenticated_items(true);
        match query.delete() {
            Ok(()) => Ok(()),
            Err(error) if error.code() == errSecItemNotFound => Err(PhotoKitKeyError::NotFound),
            Err(error) => Err(map_keychain_error(error)),
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl PhotoKitKeyPort for MacOsPhotoKitKeychain {
    fn create_root_key(&self, _key_reference: &str) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
        Err(PhotoKitKeyError::Unavailable)
    }

    fn load_root_key(
        &self,
        _key_reference: &str,
        _allow_authentication_ui: bool,
    ) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
        Err(PhotoKitKeyError::Unavailable)
    }

    fn delete_root_key(&self, _key_reference: &str) -> Result<(), PhotoKitKeyError> {
        Err(PhotoKitKeyError::Unavailable)
    }
}

fn validate_key_reference(value: &str) -> Result<(), PhotoKitKeyError> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        Err(PhotoKitKeyError::Integrity)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn map_keychain_error(error: security_framework::base::Error) -> PhotoKitKeyError {
    const ERR_SEC_AUTH_FAILED: i32 = security_framework_sys::base::errSecAuthFailed;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = security_framework_sys::base::errSecItemNotFound;
    const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

    match error.code() {
        ERR_SEC_ITEM_NOT_FOUND => PhotoKitKeyError::NotFound,
        ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => PhotoKitKeyError::Locked,
        ERR_SEC_NOT_AVAILABLE => PhotoKitKeyError::Unavailable,
        _ => PhotoKitKeyError::Internal,
    }
}
