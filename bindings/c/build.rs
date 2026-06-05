fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let crate_path = std::path::Path::new(&crate_dir);

    let config = match cbindgen::Config::from_file(crate_path.join("cbindgen.toml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cbindgen: failed to read config: {e}");
            return;
        }
    };

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            let out_dir = crate_path.join("include");
            if std::fs::create_dir_all(&out_dir).is_err() {
                eprintln!("cbindgen: failed to create include directory");
                return;
            }
            bindings.write_to_file(out_dir.join("nono.h"));
        }
        Err(e) => {
            eprintln!("cbindgen: generation failed: {e}");
        }
    }
}
