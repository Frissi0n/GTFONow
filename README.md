# GTFONow

Automatic privilege escalation for misconfigured capabilities, sudo and suid binaries.

## Features
* Automatically escalate privileges using misconfigured sudo permissions.
* Automatically escalate privileges using misconfigured suid permissions.
* Automatically escalated privileges using misconfigured capabilities.
* Supports Python 2 and 3.
* No third party libraries required.
* Support sudo PASSWD and NOPASSWD escalation, automatically attempts to enumerate sudo binaries for when `sudo -l` is not accessible.

## Usage Examples


## Roadmap
* Parse `sudo -l` for less noisy sudo privilege escalations.
* Add more types of capability escalation.

## Credits
* Payloads thanks to [GTFOBins](https://gtfobins.github.io/).
