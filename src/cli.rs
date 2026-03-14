use std::ffi::OsString;

#[derive(Debug, Clone)]
pub struct Cli {
    pub fps: Option<u32>,
    pub touch: bool,
    pub game_args: Vec<OsString>,
}

impl Cli {
    pub fn parse() -> Result<Self, String> {
        let mut fps: Option<u32> = None;
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
                _ => return Err(format!("unknown argument: {arg}\n\n{}", Self::usage())),
            }
        }

        let fps = fps.map(|f| f.clamp(10, 1000));

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
            "  --fps <N>     Target FPS (10..=1000). If omitted, FPS is not modified",
            "  --touch       Enable touch/mobile UI injection (also sets DPI scale to 5x)",
            "  -h, --help    Show this help",
        ]
        .join("\n")
    }
}
