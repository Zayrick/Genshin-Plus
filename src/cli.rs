use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Cli {
    pub game_exe: Option<PathBuf>,
    pub fps: Option<u32>,
    pub touch: bool,
    pub game_args: Vec<OsString>,
}

impl Cli {
    pub fn parse() -> Result<Self, String> {
        Self::parse_args(std::env::args_os().skip(1).collect())
    }

    fn parse_args(args: Vec<OsString>) -> Result<Self, String> {
        let mut game_exe: Option<PathBuf> = None;
        let mut fps: Option<u32> = None;
        let mut touch = false;
        let mut game_args: Vec<OsString> = Vec::new();

        let mut i = 0usize;
        while i < args.len() {
            let arg = args[i].to_string_lossy();
            if arg == "--" {
                game_args.extend_from_slice(&args[i + 1..]);
                break;
            }

            let arg_lower = arg.to_ascii_lowercase();
            match arg_lower.as_str() {
                "-h" | "--help" => return Err(Self::usage()),
                "-t" | "--touch" => {
                    touch = true;
                    i += 1;
                }
                "--game" | "--game-exe" => {
                    if game_exe.is_some() {
                        return Err("game executable specified more than once".to_string());
                    }
                    let value = args
                        .get(i + 1)
                        .ok_or_else(|| "missing value for --game".to_string())?;
                    if value.is_empty() {
                        return Err("game executable path cannot be empty".to_string());
                    }
                    game_exe = Some(PathBuf::from(value));
                    i += 2;
                }
                "--fps" => {
                    let value = args
                        .get(i + 1)
                        .ok_or_else(|| "missing value for --fps".to_string())?
                        .to_string_lossy()
                        .to_string();
                    fps = Some(
                        value
                            .parse::<f64>()
                            .map_err(|_| format!("invalid --fps value: {value}"))?
                            .round() as u32,
                    );
                    i += 2;
                }
                _ if arg_lower.starts_with("--fps=") => {
                    let value = arg_lower.trim_start_matches("--fps=");
                    fps = Some(
                        value
                            .parse::<f64>()
                            .map_err(|_| format!("invalid --fps value: {value}"))?
                            .round() as u32,
                    );
                    i += 1;
                }
                _ if arg.starts_with('-') => {
                    return Err(format!("unknown argument: {arg}\n\n{}", Self::usage()));
                }
                _ => {
                    if game_exe.is_some() {
                        return Err(format!(
                            "unexpected positional argument: {arg}\n\n{}",
                            Self::usage()
                        ));
                    }
                    game_exe = Some(PathBuf::from(&args[i]));
                    i += 1;
                }
            }
        }

        let fps = fps.map(|f| f.clamp(10, 1000));

        Ok(Self {
            game_exe,
            fps,
            touch,
            game_args,
        })
    }

    fn usage() -> String {
        [
            "Usage:",
            "  genshin_plus [<game.exe>] [--fps <N>] [--touch] [-- <game args...>]",
            "  genshin_plus --game <game.exe> [--fps <N>] [--touch] [-- <game args...>]",
            "",
            "Options:",
            "  --game <EXE>  Target game executable (also accepted as a positional argument)",
            "  --fps <N>     Target FPS (10..=1000). If omitted, FPS is not modified",
            "  --touch       Enable touch/mobile UI injection (also sets DPI scale to 5x)",
            "  -h, --help    Show this help",
            "",
            "If no game executable is supplied, .\\yuanshen.exe in the current directory is used.",
        ]
        .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_positional_game_executable_before_options() {
        let cli = Cli::parse_args(args(&[
            r"D:\Games\Genshin Impact Game\YuanShen.exe",
            "--fps",
            "144",
            "--touch",
            "--",
            "-popupwindow",
        ]))
        .unwrap();

        assert_eq!(
            cli.game_exe,
            Some(PathBuf::from(r"D:\Games\Genshin Impact Game\YuanShen.exe"))
        );
        assert_eq!(cli.fps, Some(144));
        assert!(cli.touch);
        assert_eq!(cli.game_args, args(&["-popupwindow"]));
    }

    #[test]
    fn parses_explicit_game_option_after_other_options() {
        let cli =
            Cli::parse_args(args(&["--touch", "--game", r"D:\Genshin\YuanShen.exe"])).unwrap();

        assert_eq!(
            cli.game_exe,
            Some(PathBuf::from(r"D:\Genshin\YuanShen.exe"))
        );
        assert!(cli.touch);
    }

    #[test]
    fn rejects_multiple_game_executables() {
        let err = Cli::parse_args(args(&[
            r"D:\Genshin\YuanShen.exe",
            "--game",
            r"E:\Genshin\YuanShen.exe",
        ]))
        .unwrap_err();

        assert_eq!(err, "game executable specified more than once");
    }

    #[test]
    fn keeps_game_arguments_separate_from_the_executable() {
        let cli = Cli::parse_args(args(&["--", "other.exe", "-screen-fullscreen", "1"])).unwrap();

        assert_eq!(cli.game_exe, None);
        assert_eq!(
            cli.game_args,
            args(&["other.exe", "-screen-fullscreen", "1"])
        );
    }
}
