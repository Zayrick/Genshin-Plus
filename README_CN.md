# Genshin Plus

中文文档 | [English](README.md)

一个使用 Rust 编写的轻量级原神 FPS 解锁器和移动端 UI 注入工具。

## 重要声明

**本人对游戏内存注入和逆向工程一窍不通！** 这个项目完全是基于 [winTEuser/Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker) 这个优秀的 C++ 项目转写而来的 Rust 版本。

转写这个项目的初衷纯粹是为了**个人串流需求** —— 我需要一个更便携、更易于定制的解决方案来配合我的串流设置。

## 特别鸣谢

非常感谢 **[winTEuser](https://github.com/winTEuser)** 开发的原版 [Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker) 项目！没有 ta 在逆向工程方面的出色工作和原版 C++ 实现，这个 Rust 版本根本不可能诞生。

本项目完全站在巨人的肩膀上。所有核心逻辑、特征码模式和注入技术的功劳都归属于原作者。

## 功能特性

- **帧率解锁** - 突破 60 FPS 限制，支持自定义帧率（10-1000 FPS，默认：120）
- **移动端 UI 注入** - 启用触控/移动端 UI 模式，带有 5 倍 DPI 缩放
- **多版本支持** - 兼容 3.7 至 5.5+ 版本的游戏
- **Rust 编写** - 内存安全，运行时无外部依赖
- **单文件分发** - 便携式可执行文件，无需安装

## 系统要求

- Windows 10/11 (x64)
- 原神国服客户端 (yuanshen.exe)
- 管理员权限

## 使用方法

1. 将 `genshin_plus.exe` 放置到原神游戏目录中（与 `yuanshen.exe` 同一文件夹）
2. 以管理员身份运行 `genshin_plus.exe`
3. 游戏将自动启动并应用补丁

### 命令行参数

```
用法:
  genshin_plus [--fps <N>] [--touch] [-- <游戏参数...>]

选项:
  --fps <N>     目标帧率 (10..=1000)。默认: 120
  --touch       启用触控/移动端 UI 注入（同时将 DPI 缩放设为 5 倍）
  -h, --help    显示帮助信息
```

### 使用示例

```bash
# 使用默认 120 帧启动
genshin_plus.exe

# 使用自定义 144 帧启动
genshin_plus.exe --fps 144

# 启用移动端 UI 启动
genshin_plus.exe --touch

# 使用 240 帧并启用移动端 UI
genshin_plus.exe --fps 240 --touch

# 传递额外参数给游戏
genshin_plus.exe --fps 120 -- -popupwindow

# 配合 Apollo（Sunshine 的一个 fork）串流使用
cmd /C ".\genshin_plus.exe --fps %APOLLO_CLIENT_FPS% --touch -- -screen-fullscreen 1 -screen-width %APOLLO_CLIENT_WIDTH% -screen-height %APOLLO_CLIENT_HEIGHT%"
```

## 从源码构建

### 前置要求

- Rust 工具链（推荐 1.80+，edition 2024）
- Windows SDK

### 构建步骤

```bash
# 克隆仓库
git clone https://github.com/your-username/genshin_plus.git
cd genshin_plus

# 构建发布版本
cargo build --release

# 可执行文件位于 target/release/genshin_plus.exe
```

## 项目结构

```
genshin_plus/
├── Cargo.toml          # 项目配置
├── src/
│   ├── main.rs         # 程序入口
│   ├── cli.rs          # 命令行参数解析
│   ├── genshin.rs      # 核心注入逻辑
│   ├── pattern.rs      # 特征码模式扫描
│   ├── pe.rs           # PE 文件解析
│   ├── shellcode.rs    # Shellcode 数据和常量
│   └── win.rs          # Windows API 封装
└── README.md
```

## 风险提示

- **使用风险自负。** 本工具会修改游戏内存。
- 本工具仅适用于**原神国服客户端** (yuanshen.exe)。
- 开发者不对使用本工具造成的任何后果承担责任。
- 使用第三方工具前，请务必备份游戏安装。

## 许可证

本项目基于 MIT 许可证开源 - 详见 [LICENSE](LICENSE) 文件。

## 相关项目

- [Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker) - 本项目所基于的原版 C++ 实现

---

*本项目与米哈游/HoYoverse 没有任何关联。*
