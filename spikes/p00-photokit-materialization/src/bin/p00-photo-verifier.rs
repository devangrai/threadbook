use p00_photokit_materialization::sha256_file;
use std::path::Path;

fn main() {
    if let Err(error) = verify() {
        eprintln!("verification failed: {error}");
        std::process::exit(1);
    }
}

fn verify() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().ok_or("missing path")?;
    let expected_hash = arguments.next().ok_or("missing hash")?;
    if arguments.next().is_some() {
        return Err("unexpected argument");
    }
    let expected_hash = expected_hash.to_str().ok_or("invalid hash")?;
    let actual_hash = sha256_file(Path::new(&path)).map_err(|_| "hash verification")?;
    if actual_hash != expected_hash {
        return Err("hash mismatch");
    }
    let image = image::ImageReader::open(Path::new(&path))
        .map_err(|_| "open")?
        .with_guessed_format()
        .map_err(|_| "format")?
        .decode()
        .map_err(|_| "decode")?;
    if image.width() == 0 || image.height() == 0 {
        return Err("empty image");
    }
    println!("verified");
    Ok(())
}
