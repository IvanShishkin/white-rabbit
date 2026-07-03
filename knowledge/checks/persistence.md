# Checks — persistence & IR signals (`scheduled`, `persistence_signals` sections)

Post-compromise footholds a configuration audit misses. These are "hunt" checks: most
of the time they are clean, so any hit deserves a hard look. Correlate a suspicious
cron/timer or preloaded library with the log-hunt findings for context.

### Preloaded shared library (ld.so.preload)
- **id:** persist-ld-preload
- **severity:** critical
- **look for:** any `ld_so_preload:` line (the section prints a note "absent/empty" on a clean host).
- **why:** `/etc/ld.so.preload` forces a library into *every* dynamically-linked process — the standard userland-rootkit hook for hiding files, processes, and connections. A non-empty preload on a host that didn't deliberately configure one is a strong compromise indicator.
- **fix:** `# investigate the library's origin before touching it (it may hide its own removal): dpkg -S <lib> ; stat <lib> ; then treat the host as potentially compromised and plan a rebuild if it is not accounted for`
- **mitre:** T1574.006 (Dynamic Linker Hijacking)

### Process running a deleted binary
- **id:** persist-deleted-binary
- **severity:** high
- **look for:** any `deleted_binary_proc:` line (clean host prints "no deleted-binary processes").
- **why:** A running process whose on-disk executable was unlinked is typical of malware that deletes itself after launch to evade file-based detection while staying resident. (Benign causes exist — a package upgraded while its daemon kept running — so confirm before acting.)
- **fix:** `# identify it before killing: ls -l /proc/<pid>/exe ; cat /proc/<pid>/cmdline | tr '\\0' ' ' ; ps -p <pid> -o user,ppid,lstart,cmd . If unexplained, capture /proc/<pid>/exe for forensics, then treat as compromise.`
- **mitre:** T1070.004 (File Deletion) + T1055 (Process Injection)

### Suspicious scheduled job (cron / systemd timer)
- **id:** persist-malicious-cron
- **severity:** high
- **look for:** in `scheduled`, a job that pipes a network fetch into a shell (`curl … | bash`, `wget … | sh`), runs something out of `/tmp`, `/dev/shm`, or a dot-directory, base64-decodes, or belongs to a user who shouldn't have cron. Check both the system crontab lines and every `user crontab:` block.
- **why:** Cron and systemd timers are the most common re-execution/persistence mechanism — they re-run attacker code on a schedule and survive reboots.
- **fix:** `# for the owning user: crontab -l -u <user> ; inspect /etc/cron.d, /etc/cron.*, and 'systemctl list-timers'. Remove the entry only after capturing what it runs; investigate how it was installed.`
- **mitre:** T1053.003 (Cron) + T1053.006 (Systemd Timers)

### rc.local / startup script present
- **id:** persist-rc-local
- **severity:** medium
- **look for:** any `rc_local:` line — `/etc/rc.local` exists and runs commands at boot.
- **why:** `rc.local` is deprecated on modern systemd hosts; when present it is often either legacy config or a boot-persistence mechanism. Any command it launches runs as root at every boot.
- **fix:** `# review what it runs; if legitimate, migrate to a proper systemd unit; if unexpected, treat as persistence and trace its origin`
- **mitre:** T1037 (Boot or Logon Initialization Scripts)

### Unexpected SUID binary
- **id:** persist-suid-unexpected
- **severity:** medium
- **look for:** a `suid:` line for a binary outside the normal set (a copy of `bash`/`sh`/`dash`, or anything in `/usr/local` you didn't install). Standard SUID tools (`sudo`, `su`, `passwd`, `mount`, `ping`, `pkexec`, `newgrp`, `chsh`, `chfn`, `gpasswd`) are expected.
- **why:** A SUID-root shell or custom SUID binary is a trivial privilege-escalation backdoor — any user who can execute it becomes root.
- **fix:** `# verify ownership/package: dpkg -S <path> ; ls -l <path>. A SUID shell is never legitimate — remove the SUID bit (sudo chmod u-s <path>) after confirming it isn't a decoy, and investigate.`
- **mitre:** T1548.001 (Setuid and Setgid)
