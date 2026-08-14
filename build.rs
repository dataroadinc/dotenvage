//! Build script to install Git hooks via Rhusky.
fn main() {
    rhusky::Rhusky::new()
        .hooks_dir(".githooks")
        .skip_in_env("GITHUB_ACTIONS")
        .with_default_hooks()
        .install_from_build_script()
        .expect("failed to install repository Git hooks");
}
