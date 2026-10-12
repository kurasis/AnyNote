// Share preserved GPL provider sources without changing their old crate or locks.
// Build outputs alone are copied. Conventional hello/mod.rs keeps Rust submodule
// resolution identical on Linux/MSVC; no source patching or generated crypto.
use std::{env, fs, path::Path};
fn copy(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        let out = to.join(e.file_name());
        if p.is_dir() {
            copy(&p, &out);
        } else {
            fs::copy(&p, &out).unwrap();
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
}
fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let base = Path::new(&manifest).join("../../experiments/p01/windows-hello/src");
    let out = env::var("OUT_DIR").unwrap();
    let out = Path::new(&out).join("provider");
    copy(&base.join("hello"), &out.join("hello"));
    for name in ["filesystem.rs", "storage.rs"] {
        fs::copy(base.join(name), out.join(name)).unwrap();
        println!("cargo:rerun-if-changed={}", base.join(name).display());
    }
    fs::copy(base.join("hello.rs"), out.join("hello/mod.rs")).unwrap();
    println!("cargo:rerun-if-changed={}", base.join("hello.rs").display());
    let glue = format!(
        "#[path={:?}] #[allow(dead_code,clippy::collapsible_if)] pub(crate) mod filesystem;\n#[path={:?}] #[allow(dead_code)] pub(crate) mod storage;\n#[path={:?}] pub(crate) mod hello;\n",
        out.join("filesystem.rs"),
        out.join("storage.rs"),
        out.join("hello/mod.rs")
    );
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("provider.rs"),
        glue,
    )
    .unwrap();
}
