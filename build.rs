use embed_manifest::manifest::ExecutionLevel;
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // Start normally so launchers that use CreateProcess can run the
        // bootstrap. The program then requests elevation with ShellExecuteW.
        let manifest =
            new_manifest("Genshin.Plus").requested_execution_level(ExecutionLevel::AsInvoker);

        embed_manifest(manifest).expect("failed to embed the Windows application manifest");
    }

    println!("cargo:rerun-if-changed=build.rs");
}
