mod cli;
mod genshin;
mod pattern;
mod pe;
mod shellcode;
mod win;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = cli::Cli::parse()?;
    genshin::run(&cli)?;
    Ok(())
}
