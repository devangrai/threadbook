#[cfg(all(target_os = "macos", feature = "photokit-native"))]
use std::fs::File;
#[cfg(all(target_os = "macos", feature = "photokit-native"))]
use std::os::fd::AsRawFd;
#[cfg(all(target_os = "macos", feature = "photokit-native"))]
use wardrobe_platform::PhotoKitNativePort;
use wardrobe_platform::{PhotoKitNativeError, ProductionPhotoKitNativePort};

#[cfg(all(target_os = "macos", feature = "photokit-native"))]
#[test]
fn production_adapter_uses_real_abi_and_transfers_descriptor_ownership() {
    let mut adapter =
        ProductionPhotoKitNativePort::new().expect("create production PhotoKit handle");
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("invalid.jpeg");
    std::fs::write(&path, b"not-an-image").unwrap();
    let descriptor = File::open(path).unwrap();
    let raw_descriptor = descriptor.as_raw_fd();

    assert_eq!(
        adapter.validate_image(descriptor, "public.jpeg"),
        Err(PhotoKitNativeError::ImageValidation)
    );
    assert_eq!(unsafe { libc::fcntl(raw_descriptor, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );

    drop(adapter);
}

#[cfg(not(all(target_os = "macos", feature = "photokit-native")))]
#[test]
fn production_adapter_requires_native_feature_or_macos() {
    assert!(matches!(
        ProductionPhotoKitNativePort::new(),
        Err(PhotoKitNativeError::Unavailable)
    ));
}
