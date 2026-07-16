use std::fs;
use std::path::PathBuf;

fn main() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/desktop-ui/src/generated/contracts.ts");
    fs::create_dir_all(path.parent().expect("generated binding parent"))
        .expect("create generated binding directory");
    fs::write(&path, wardrobe_core::typescript_bindings()).expect("write generated bindings");
    println!("{}", path.display());
}
