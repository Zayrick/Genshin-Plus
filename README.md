# Genshin Plus

[中文文档](README_CN.md) | English

A lightweight Genshin Impact FPS unlocker and mobile UI injector written in Rust.

## Important Disclaimer

**I have absolutely NO prior experience with game memory injection or reverse engineering.** This project is a Rust rewrite based on the excellent C++ implementation by [winTEuser/Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker).

The motivation behind this rewrite was purely for **personal streaming needs** - I needed a more portable and customizable solution for my streaming setup.

## Special Thanks

Huge thanks to **[winTEuser](https://github.com/winTEuser)** for the original [Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker) project! Without their incredible work on reverse engineering and the original C++ implementation, this Rust version would not have been possible.

This project stands on the shoulders of giants. All credit for the core logic, signature patterns, and injection techniques goes to the original developer.

## Features

- **FPS Unlock** - Bypass the 60 FPS limit, supports custom frame rates (10-1000 FPS)
- **Mobile UI Injection** - Enable touch/mobile UI mode with custom DPI scaling (5x)
- **Multi-Version Support** - Compatible with game versions from 3.7 to 5.5+
- **Custom Game Path** - Prefer a game executable supplied on the command line; the unlocker no longer has to be in the game directory
- **Automatic Elevation Request** - Detects the current token and relaunches through Windows `runas` while preserving all arguments
- **Written in Rust** - Memory safe, no external dependencies at runtime
- **Single Binary** - Portable executable, no installation required

## Requirements

- Windows 10/11 (x64)
- Genshin Impact (Chinese client - yuanshen.exe)
- Administrator privileges (requested automatically at startup; the user must still approve UAC)

## Usage

1. Pass the game executable as the first positional argument, for example:
   `genshin_plus.exe "D:\Genshin Impact\Genshin Impact Game\YuanShen.exe" --fps 120`
2. Approve the Windows UAC prompt
3. The game will launch automatically with the patches applied

You can also supply the path with `--game <EXE>`. If no game executable is supplied, the backward-compatible fallback is `yuanshen.exe` in the current working directory. A command-line executable always takes priority.

### Command Line Options

```
Usage:
  genshin_plus [<game.exe>] [--fps <N>] [--touch] [-- <game args...>]
  genshin_plus --game <game.exe> [--fps <N>] [--touch] [-- <game args...>]

Options:
  --game <EXE>  Target game executable (also accepted as the first positional argument)
  --fps <N>     Target FPS (10..=1000). If omitted, FPS is not modified
  --touch       Enable touch/mobile UI injection (also sets DPI scale to 5x)
  -h, --help    Show this help
```

### Examples

```bash
# Prefer a game executable supplied on the command line (spaces are supported)
genshin_plus.exe "D:\Genshin Impact\Genshin Impact Game\YuanShen.exe" --fps 120

# Equivalent --game form
genshin_plus.exe --game "D:\Genshin Impact\Genshin Impact Game\YuanShen.exe" --fps 120

# Launch with custom 144 FPS
genshin_plus.exe --fps 144

# Launch with mobile UI enabled
genshin_plus.exe --touch

# Launch with 240 FPS and mobile UI
genshin_plus.exe --fps 240 --touch

# Pass additional arguments to the game
genshin_plus.exe --fps 120 -- -popupwindow

# Use with Apollo (a Sunshine fork) for game streaming
cmd /C .\genshin_plus.exe "D:\Genshin Impact\Genshin Impact Game\YuanShen.exe" --fps %APOLLO_CLIENT_FPS% --touch -- -screen-fullscreen 1 -screen-width %APOLLO_CLIENT_WIDTH% -screen-height %APOLLO_CLIENT_HEIGHT%
```

## Building from Source

### Prerequisites

- Rust toolchain (1.80+ recommended, edition 2024)
- Windows SDK

### Build

```bash
# Clone the repository
git clone https://github.com/your-username/genshin_plus.git
cd genshin_plus

# Build release version
cargo build --release

# The binary will be at target/release/genshin_plus.exe
```

## Project Structure

```
genshin_plus/
├── build.rs           # Embeds the Windows application manifest
├── Cargo.toml          # Project configuration
├── src/
│   ├── main.rs         # Entry point
│   ├── cli.rs          # Command line argument parsing
│   ├── genshin.rs      # Core injection logic
│   ├── pattern.rs      # Signature pattern scanning
│   ├── pe.rs           # PE file parsing
│   ├── shellcode.rs    # Shellcode data and constants
│   └── win.rs          # Windows API wrappers
└── README.md
```

## Risks and Warnings

- **Use at your own risk.** This tool modifies game memory.
- This tool is designed for the **Chinese version** of Genshin Impact (yuanshen.exe).
- The developer takes no responsibility for any consequences of using this tool.
- Always back up your game installation before using third-party tools.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker) - The original C++ implementation that this project is based on

---

*This project is not affiliated with miHoYo/HoYoverse in any way.*
