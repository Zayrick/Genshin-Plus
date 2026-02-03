use std::ffi::OsString;

#[derive(Debug, Clone)]
pub struct Cli {
    pub fps: u32,
    pub touch: bool,
    pub game_args: Vec<OsString>,
}

impl Cli {
    pub fn parse() -> Result<Self, String> {
        let mut fps: u32 = 120;
        let mut touch = false;
        let mut game_args: Vec<OsString> = Vec::new();

        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
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
                "--fps" => {
                    let value = args
                        .get(i + 1)
                        .ok_or_else(|| "missing value for --fps".to_string())?
                        .to_string_lossy()
                        .to_string();
                    fps = value
                        .parse::<u32>()
                        .map_err(|_| format!("invalid --fps value: {value}"))?;
                    i += 2;
                }
                _ if arg_lower.starts_with("--fps=") => {
                    let value = arg_lower.trim_start_matches("--fps=");
                    fps = value
                        .parse::<u32>()
                        .map_err(|_| format!("invalid --fps value: {value}"))?;
                    i += 1;
                }
                _ => return Err(format!("unknown argument: {arg}\n\n{}", Self::usage())),
            }
        }

        fps = fps.clamp(10, 1000);

        Ok(Self {
            fps,
            touch,
            game_args,
        })
    }

    fn usage() -> String {
        [
            "Usage:",
            "  genshin_plus [--fps <N>] [--touch] [-- <game args...>]",
            "",
            "Options:",
            "  --fps <N>     Target FPS (10..=1000). Default: 120",
            "  --touch       Enable touch/mobile UI injection (also sets DPI scale to 5x)",
            "  -h, --help    Show this help",
        ]
        .join("\n")
    }
}
