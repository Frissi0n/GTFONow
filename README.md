# GTFONow

Automatic privilege escalation for misconfigured capabilities, sudo and suid binaries.

## Features
* Automatically escalate privileges using misconfigured sudo permissions.
* Automatically escalate privileges using misconfigured suid permissions.
* Automatically escalated privileges using misconfigured capabilities.
* Supports Python 2 and 3.
* No third party libraries required.
* Support sudo `PASSWD` and `NOPASSWD` escalation, automatically attempts to enumerate sudo binaries for when password is not known and `sudo -l` is not accessible.

## Usage Examples

### Default Mode - Scan All

[![asciicast](https://asciinema.org/a/CyEH3GyAFyWtIVjngWpa0hDBk.svg)](https://asciinema.org/a/CyEH3GyAFyWtIVjngWpa0hDBk)

### Capability Escalation

[![asciicast](https://asciinema.org/a/nmrMirrKNRrb7XHhVRYD66tWa.svg)](https://asciinema.org/a/nmrMirrKNRrb7XHhVRYD66tWa)

### Sudo Escalation and Verbose Mode

[![asciicast](https://asciinema.org/a/HdpWGxGAIAMahoJD6eoB6pqNq.svg)](https://asciinema.org/a/HdpWGxGAIAMahoJD6eoB6pqNq)

## Todo
* Parse `sudo -l` for less noisy sudo privilege escalations.
* Add more types of capability escalation.

## Credits
* Payloads thanks to [GTFOBins](https://gtfobins.github.io/).
