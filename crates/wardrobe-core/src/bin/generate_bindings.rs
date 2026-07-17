use std::path::PathBuf;

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../apps/desktop-ui/src/generated/contracts.ts")
        });
    std::fs::write(&path, wardrobe_core::typescript_bindings())
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
}
