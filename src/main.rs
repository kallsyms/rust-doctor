use clap::Parser;
use rust_doctor::cli::Cli;

fn main() {
    let cli = Cli::parse();
    // Avoid "unused variable" warning for `runner` in case of early exit.
    let runner = rust_doctor::cli::Runner::new(cli);
    if let Err(e) = runner.run() {
        eprintln!("rust-doctor error: {e}");
        std::process::exit(2);
    }
}
