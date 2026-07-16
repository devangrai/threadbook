// P09-UPG-001: release identity must be fixed and internally consistent at build time.
#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

use std::fs;
use std::path::Path;
use tempfile::TempDir;

const APPLICATION_ID: &str = "com.devrai.wardrobe";
const VERSION: &str = "0.1.0";

fn write_fixture(root: &Path) {
    fs::create_dir_all(root.join("release")).unwrap();
    fs::create_dir_all(root.join("src-tauri")).unwrap();
    fs::create_dir_all(root.join("apps/desktop-ui")).unwrap();
    fs::write(
        root.join("release/wardrobe-build-metadata-v1.json"),
        format!(
            r#"{{"schema_version":1,"application_id":"{APPLICATION_ID}","application_version":"{VERSION}","release_sequence":1}}"#
        ),
    )
    .unwrap();
    fs::write(
        root.join("src-tauri/Cargo.toml"),
        format!("[package]\nname = \"wardrobe-desktop\"\nversion = \"{VERSION}\"\n"),
    )
    .unwrap();
    fs::write(
        root.join("src-tauri/tauri.conf.json"),
        format!(r#"{{"identifier":"{APPLICATION_ID}","version":"{VERSION}"}}"#),
    )
    .unwrap();
    fs::write(
        root.join("package.json"),
        format!(r#"{{"name":"wardrobe","version":"{VERSION}"}}"#),
    )
    .unwrap();
    fs::write(
        root.join("apps/desktop-ui/package.json"),
        format!(r#"{{"name":"@wardrobe/desktop-ui","version":"{VERSION}"}}"#),
    )
    .unwrap();
}

#[test]
fn aligned_metadata_generates_installed_update_constants() {
    let fixture = TempDir::new().unwrap();
    write_fixture(fixture.path());

    let generated = build_script::generated_metadata_constants(fixture.path()).unwrap();

    assert!(generated.contains(
        r#"pub const INSTALLED_UPDATE_APPLICATION_ID_V1: &str = "com.devrai.wardrobe";"#
    ));
    assert!(
        generated.contains(r#"pub const INSTALLED_UPDATE_APPLICATION_VERSION_V1: &str = "0.1.0";"#)
    );
    assert!(generated.contains("pub const INSTALLED_UPDATE_RELEASE_SEQUENCE_V1: u64 = 1;"));
}

#[test]
fn every_application_version_source_must_match_metadata_exactly() {
    let cases = [
        ("src-tauri/Cargo.toml", "[package]\nversion = \"0.1.1\"\n"),
        (
            "src-tauri/tauri.conf.json",
            r#"{"identifier":"com.devrai.wardrobe","version":"0.1.1"}"#,
        ),
        ("package.json", r#"{"version":"0.1.1"}"#),
        ("apps/desktop-ui/package.json", r#"{"version":"0.1.1"}"#),
    ];

    for (relative_path, contents) in cases {
        let fixture = TempDir::new().unwrap();
        write_fixture(fixture.path());
        fs::write(fixture.path().join(relative_path), contents).unwrap();

        let error = build_script::generated_metadata_constants(fixture.path()).unwrap_err();

        assert!(error.contains("application version mismatch"), "{error}");
        assert!(error.contains(relative_path), "{error}");
    }
}

#[test]
fn tauri_identifier_must_match_metadata_exactly() {
    let fixture = TempDir::new().unwrap();
    write_fixture(fixture.path());
    fs::write(
        fixture.path().join("src-tauri/tauri.conf.json"),
        r#"{"identifier":"com.example.wardrobe","version":"0.1.0"}"#,
    )
    .unwrap();

    let error = build_script::generated_metadata_constants(fixture.path()).unwrap_err();

    assert!(error.contains("application identifier mismatch"), "{error}");
}

#[test]
fn metadata_schema_and_release_sequence_are_fail_closed() {
    for metadata in [
        r#"{"schema_version":2,"application_id":"com.devrai.wardrobe","application_version":"0.1.0","release_sequence":1}"#,
        r#"{"schema_version":1,"application_id":"com.devrai.wardrobe","application_version":"0.1.0","release_sequence":0}"#,
        r#"{"schema_version":1,"application_id":"com.devrai.wardrobe","application_version":"0.1.0","release_sequence":9007199254740992}"#,
        r#"{"schema_version":1,"application_id":"com.devrai.wardrobe","application_version":"0.1.0","release_sequence":1,"unexpected":true}"#,
    ] {
        let fixture = TempDir::new().unwrap();
        write_fixture(fixture.path());
        fs::write(
            fixture
                .path()
                .join("release/wardrobe-build-metadata-v1.json"),
            metadata,
        )
        .unwrap();

        assert!(
            build_script::generated_metadata_constants(fixture.path()).is_err(),
            "{metadata}"
        );
    }
}
