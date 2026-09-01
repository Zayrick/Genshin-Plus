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
    if win::relaunch_as_admin_if_needed()? {
        return Ok(());
    }

    let cli = cli::Cli::parse()?;
    genshin::run(&cli)?;
    Ok(())
}
