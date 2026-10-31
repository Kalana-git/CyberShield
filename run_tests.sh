#!/usr/bin/bash
#==============================================================================
# run_tests.sh - Automated test suite for the four CyberShield scripts (v2)
# Usage : sudo ./run_tests.sh [folder-with-the-scripts]   (run as root, on a
#         throw-away test machine: it creates and deletes users and files)
# Output: one PASS/FAIL line per test, evidence in /tmp/cs/evidence/<ID>.txt,
#         table in /tmp/cs/results.tsv (copied next to this script)
# Notes : ssh, mail, pg_dump, systemctl, journalctl, getenforce, restorecon and
#         selinuxenabled are replaced by tiny stub programs, so no real servers
#         or SELinux are needed. Everything else (GPG, useradd, chmod, df,
#         flock, /proc) is real.
#==============================================================================
set -u
if [ -n "${1:-}" ]; then
    SRC="$1"
elif [ -f "$(dirname "$0")/backup.sh" ]; then
    SRC="$(cd "$(dirname "$0")" && pwd)"
else
    SRC="$(cd "$(dirname "$0")/.." && pwd)"
fi
T=/tmp/cs
rm -rf "$T"; mkdir -p "$T"/{stubs,bin,logs,backup,remote,data,evidence,logsrc,state,reports,conf}
cp "$SRC"/*.sh "$T/bin/"; chmod 755 "$T"/bin/*.sh; chmod 755 "$T" "$T/bin"
PASS=0; FAIL=0; SKIP=0
: > "$T/results.tsv"

# ---------------- stub programs ----------------
cat > "$T/stubs/ssh" << 'S'
#!/bin/bash
while [ "${1:-}" = "-o" ]; do shift 2; done
target=$1; shift; host=${target#*@}
if [ "${STUB_SSH_FAIL_HOST:-}" = "$host" ]; then echo "ssh: connect to host $host: refused" >&2; exit 255; fi
exec bash -c "$*"
S
cat > "$T/stubs/pg_dump" << 'S'
#!/bin/bash
[ -n "${PG_FAIL:-}" ] && { echo "pg_dump: error: connection failed" >&2; exit 1; }
[ -n "${PG_EMPTY:-}" ] && exit 0
for i in $(seq 1 200); do echo "-- fake dump of $1 row $i"; done
S
cat > "$T/stubs/mail" << 'S'
#!/bin/bash
echo "MAIL to=$* :: $(cat)" >> /tmp/cs/mail.out
S
cat > "$T/stubs/systemctl" << 'S'
#!/bin/bash
case "$1" in
  show) for u in ${STUB_MISSING:-}; do [ "$u" = "$5" ] && { echo not-found; exit 0; }; done; echo loaded ;;
  is-active) shift; [ "$1" = "--quiet" ] && shift
             for u in ${STUB_DOWN:-}; do [ "$u" = "$1" ] && exit 3; done; exit 0 ;;
esac
S
cat > "$T/stubs/getenforce" << 'S'
#!/bin/bash
echo "${STUB_SELINUX:-Enforcing}"
S
printf '#!/bin/bash\nexit 0\n' > "$T/stubs/selinuxenabled"
cat > "$T/stubs/restorecon" << 'S'
#!/bin/bash
echo "restorecon $*" >> /tmp/cs/restorecon.log
S
cat > "$T/stubs/journalctl" << 'S'
#!/bin/bash
cat /tmp/cs/logsrc/journal.txt
S
chmod +x "$T"/stubs/*
SP="$T/stubs:$PATH"
for d in tar chpasswd chmod; do mkdir -p "$T/fail_$d"; printf '#!/bin/bash\necho "%s: simulated failure" >&2\nexit 2\n' "$d" > "$T/fail_$d/$d"; chmod +x "$T/fail_$d/$d"; done
mkdir -p "$T/stubs_nproc"; printf '#!/bin/bash\necho 0\n' > "$T/stubs_nproc/nproc"; chmod +x "$T/stubs_nproc/nproc"

# ---------------- harness ----------------
t() { # t ID "description" expected_exit "regex or empty" command...
    local id=$1 desc=$2 exp=$3 pat=$4; shift 4
    local out rc ok=1 why="" res
    out=$("$@" 2>&1); rc=$?
    { echo "$out"; echo "[exit code: $rc]"; } > "$T/evidence/$id.txt"
    if [ "$rc" -ne "$exp" ]; then ok=0; why="exit $rc, expected $exp"; fi
    if [ -n "$pat" ] && ! grep -Eq -- "$pat" <<< "$out"; then ok=0; why="$why; output lacks /$pat/"; fi
    if [ "$ok" -eq 1 ]; then PASS=$((PASS+1)); res=PASS; else FAIL=$((FAIL+1)); res=FAIL; fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$desc" "exit $exp${pat:+, output /$pat/}" "exit $rc" "$res" >> "$T/results.tsv"
    printf '%-5s %-4s %s %s\n' "$id" "$res" "$desc" "${why:+($why)}"
}
check() { t "$1" "$2" 0 "" bash -c "$3"; }
skip() { SKIP=$((SKIP+1)); printf '%s\t%s\t-\t%s\tSKIP\n' "$1" "$2" "$3" >> "$T/results.tsv"; printf '%-5s SKIP %s (%s)\n' "$1" "$2" "$3"; }
piped() { local input=$1; shift; printf '%s\n' "$input" | "$@"; }
mkconf() { printf '%s\n' "$2" > "$T/conf/$1"; chmod 600 "$T/conf/$1"; echo "$T/conf/$1"; }
cd "$T" || exit 1

#==================== STRUCTURE (guide section 5.1) =====================
echo "== structure =="
for s in backup monitor log_analyzer user_mgmt; do
  f="$T/bin/$s.sh"
  t "S-$s-1" "$s.sh: bash syntax check (bash -n)" 0 "" bash -n "$f"
  if command -v shellcheck >/dev/null 2>&1; then
    t "S-$s-2" "$s.sh: ShellCheck reports nothing" 0 "" shellcheck "$f"
  else
    skip "S-$s-2" "$s.sh: ShellCheck" "shellcheck is not installed"
  fi
  check "S-$s-3" "$s.sh: shebang, strict mode, ERR+EXIT traps, header fields" "head -1 $f | grep -q '^#!/usr/bin/bash' && grep -q '^set -Eeuo pipefail' $f && grep -q \"trap 'on_err\" $f && grep -q 'trap cleanup EXIT' $f && grep -q '^# Version' $f && grep -q '^# Purpose' $f && grep -q '^# Usage' $f && grep -q '^# Needs' $f && grep -q '^# Exit' $f"
  t "S-$s-4" "$s.sh: --version" 0 "$s.sh 2.0.0" "$f" --version
  t "S-$s-5" "$s.sh: --help shows the header" 0 "Purpose" "$f" --help
  t "S-$s-6" "$s.sh: unknown option rejected" 2 "Unknown option" "$f" --bogus
done

#==================== BACKUP =====================
echo "== backup.sh =="
printf 'correct horse battery staple\n' > "$T/backup.pass"; chmod 600 "$T/backup.pass"
mkdir -p "$T/remote/threat-analysis"; for i in 1 2 3; do echo "event $i" > "$T/remote/threat-analysis/log$i.txt"; done
BE=(env PATH="$SP" BACKUP_DIR="$T/backup" LOG_FILE="$T/logs/backup.log" LOCK_FILE="$T/backup.lock" GPG_PASS_FILE="$T/backup.pass" TAS_LOG_PARENT="$T/remote" MIN_FREE_MB=1 CS_CONF=/nonexistent)
B="$T/bin/backup.sh"
t B1 "Normal encrypted backup" 0 "Backup finished" "${BE[@]}" "$B"
check B2 "2 encrypted archives + 2 checksum files created" '[ $(ls /tmp/cs/backup | grep -c "\.gpg$") -eq 2 ] && [ $(ls /tmp/cs/backup | grep -c "\.sha256$") -eq 2 ]'
check B3 "Archives private (600), folder 700" '[ "$(stat -c %a /tmp/cs/backup)" = 700 ] && [ "$(stat -c %a /tmp/cs/backup/db_*.gpg)" = 600 ]'
check B4 "No readable plain text inside the archive" '! grep -aq "fake dump" /tmp/cs/backup/db_*.gpg'
check B5 "Archive decrypts to the dump" 'gpg --batch -q --pinentry-mode loopback --passphrase-file /tmp/cs/backup.pass -d /tmp/cs/backup/db_*.gpg | gunzip | grep -q "fake dump of cybershield"'
check B6 "Checksum file verifies" 'cd /tmp/cs/backup && sha256sum -c --quiet db_*.sha256'
check B7 "No .partial files left behind" '[ -z "$(ls /tmp/cs/backup | grep partial)" ]'
DBF=$(ls "$T"/backup/db_*.gpg)
t B8 "--verify accepts a good backup" 0 "Content OK" "${BE[@]}" "$B" --verify "$DBF"
cp "$DBF" "$T/backup/tampered.sql.gz.gpg"; cp "$DBF.sha256" "$T/backup/tampered.sql.gz.gpg.sha256"; sed -i 's/db_cybershield_[0-9_]*\.sql\.gz\.gpg/tampered.sql.gz.gpg/' "$T/backup/tampered.sql.gz.gpg.sha256"; printf 'X' >> "$T/backup/tampered.sql.gz.gpg"
t B9 "--verify detects a modified backup" 1 "Checksum mismatch" "${BE[@]}" "$B" --verify "$T/backup/tampered.sql.gz.gpg"
rm -f "$T"/backup/tampered*
t B10 "--verify: checksum file missing" 3 "Checksum file missing" bash -c "cp $DBF $T/backup/nosum.gpg; ${BE[*]} $B --verify $T/backup/nosum.gpg"
rm -f "$T/backup/nosum.gpg"
t B11 "--verify: file missing" 3 "not found" "${BE[@]}" "$B" --verify "$T/backup/none.gpg"
rm -f "$T"/backup/*
t B12 "Plain mode (ENCRYPT=no)" 0 "Backup finished" "${BE[@]}" ENCRYPT=no "$B"
check B13 "Plain archives pass gzip -t" 'gzip -t /tmp/cs/backup/db_*.sql.gz && gzip -t /tmp/cs/backup/tas_logs_*.tar.gz'
rm -f "$T"/backup/*
t B14 "Empty DB_NAME skips the database dump" 0 "database backup skipped" "${BE[@]}" DB_NAME= "$B"
check B15 "Only the log archive exists" '[ -z "$(ls /tmp/cs/backup | grep ^db_)" ] && [ -n "$(ls /tmp/cs/backup | grep ^tas_logs_)" ]'
rm -f "$T"/backup/*
t B16 "Dry run only checks" 0 "DRY-RUN: would create" "${BE[@]}" "$B" --dry-run
check B17 "Dry run created no files" '[ -z "$(ls /tmp/cs/backup)" ]'
t B18 "Not root is refused" 4 "Run this script as root" su -s /bin/bash nobody -c "$B"
chmod 644 "$T/backup.pass"
t B19 "World-readable passphrase file refused" 3 "must be private" "${BE[@]}" "$B"
chmod 600 "$T/backup.pass"
t B20 "Missing passphrase file refused" 3 "Passphrase file not readable" "${BE[@]}" GPG_PASS_FILE="$T/nope.pass" "$B"
t B21 "DB server unreachable" 1 "Cannot connect to 192.168.2.10" "${BE[@]}" STUB_SSH_FAIL_HOST=192.168.2.10 "$B"
t B22 "Log server unreachable" 1 "Cannot connect to 192.168.2.20" "${BE[@]}" STUB_SSH_FAIL_HOST=192.168.2.20 "$B"
rm -f "$T"/backup/*
t B23 "pg_dump fails: error reported" 1 "Database backup failed" "${BE[@]}" PG_FAIL=1 "$B"
check B24 "Failed dump left no file" '[ -z "$(ls /tmp/cs/backup)" ]'
t B25 "Empty dump rejected" 1 "empty or corrupt" "${BE[@]}" PG_EMPTY=1 "$B"
check B26 "Rejected dump left no file" '[ -z "$(ls /tmp/cs/backup)" ]'
( flock 9; sleep 6 ) 9> "$T/backup.lock" & sleep 1
t B27 "Second instance while one runs" 6 "already running" "${BE[@]}" "$B"
wait
t B28 "Not enough free disk space" 1 "MB free" "${BE[@]}" MIN_FREE_MB=999999999 "$B"
t B29 "Injection attempt in DB_NAME refused" 2 "Invalid DB_NAME" "${BE[@]}" 'DB_NAME=x;rm -rf /' "$B"
t B30 "Non-numeric KEEP_DAYS refused" 2 "KEEP_DAYS must be" "${BE[@]}" KEEP_DAYS=abc "$B"
t B31 "Relative BACKUP_DIR refused" 2 "absolute path" "${BE[@]}" BACKUP_DIR=backup "$B"
t B32 "BACKUP_DIR=/ refused" 2 "absolute path" "${BE[@]}" BACKUP_DIR=/ "$B"
touch -d "40 days ago" "$T/backup/db_cybershield_OLD.sql.gz.gpg" "$T/backup/db_cybershield_OLD.sql.gz.gpg.sha256"
touch -d "5 days ago"  "$T/backup/db_cybershield_RECENT.sql.gz.gpg"
echo keep > "$T/backup/notes.txt"; touch -d "90 days ago" "$T/backup/notes.txt"
t B33 "Retention deletes old backups" 0 "Deleted old backup: db_cybershield_OLD" "${BE[@]}" "$B"
check B34 "Old gone, recent kept, unrelated file untouched" '[ ! -e /tmp/cs/backup/db_cybershield_OLD.sql.gz.gpg ] && [ -e /tmp/cs/backup/db_cybershield_RECENT.sql.gz.gpg ] && [ -e /tmp/cs/backup/notes.txt ]'
rm -rf "$T/backup"; : > "$T/restorecon.log"
t B35 "New backup folder is created and SELinux label restored" 0 "Created backup directory" "${BE[@]}" "$B"
check B36 "restorecon was called on the new folder" 'grep -q "restorecon -R -- /tmp/cs/backup" /tmp/cs/restorecon.log'
rm -rf "$T/backup"
t B37 "Unexpected command failure reported with line number (chmod fails)" 1 "Unexpected failure \(exit [0-9]+\) at line [0-9]+" "${BE[@]}" PATH="$T/fail_chmod:$SP" "$B"
rm -rf "$T/backup"; mkdir -p "$T/backup"
# configuration file behaviour
C1=$(mkconf c1.conf $'# test config\nKEEP_DAYS=5\nDB_NAME="cybershield"')
t B38 "Setting read from the config file (KEEP_DAYS=5)" 0 "older than 5 days" "${BE[@]}" CS_CONF="$C1" "$B"
t B39 "Environment overrides the config file" 0 "older than 9 days" "${BE[@]}" CS_CONF="$C1" KEEP_DAYS=9 "$B"
t B40 "-c option selects the config file" 0 "older than 5 days" "${BE[@]}" "$B" -c "$C1"
C2=$(mkconf c2.conf $'KEEP_DAYS=7\nPATH=/evil\nFOO=bar')
t B41 "Unknown/dangerous keys in config are ignored with a warning" 0 "ignoring unknown setting 'PATH'" "${BE[@]}" CS_CONF="$C2" "$B"
C3=$(mkconf c3.conf 'KEEP_DAYS=$(touch /tmp/cs/pwned)')
t B42 "Command substitution in config is NOT executed" 2 "KEEP_DAYS must be" "${BE[@]}" CS_CONF="$C3" "$B"
check B43 "...and no file was created by it" '[ ! -e /tmp/cs/pwned ]'
chmod 666 "$C1"
t B44 "World-writable config file refused" 3 "refusing to read" "${BE[@]}" CS_CONF="$C1" "$B"
chmod 600 "$C1"
t B45 "Non-root-owned config file refused" 3 "refusing to read" bash -c "chown nobody $C1; ${BE[*]} CS_CONF=$C1 $B"
chown root "$C1"

#==================== MONITOR =====================
echo "== monitor.sh =="
M="$T/bin/monitor.sh"
ME=(env PATH="$SP" LOG_FILE="$T/logs/monitor.log" METRICS_CSV="$T/logs/metrics.csv" STATE_DIR="$T/state" LOCK_FILE="$T/monitor.lock" CPU_LIMIT=100 MEM_LIMIT=100 DISK_LIMIT=100 LOAD_FACTOR=1000 CS_CONF=/nonexistent)
t M1 "All readings normal" 0 "All checks passed" "${ME[@]}" "$M"
check M2 "Log has CPU, memory, disk, load, SELinux lines with level and script name" 'grep -q "\[INFO\] monitor.sh: CPU used" /tmp/cs/logs/monitor.log && grep -q "Memory used" /tmp/cs/logs/monitor.log && grep -q "Disk / used" /tmp/cs/logs/monitor.log && grep -q "Load average" /tmp/cs/logs/monitor.log && grep -q "SELinux mode: Enforcing" /tmp/cs/logs/monitor.log'
check M3 "Metrics CSV has a header and one data row" '[ "$(head -1 /tmp/cs/logs/metrics.csv)" = "timestamp,cpu_pct,mem_pct,disk_max_pct,disk_max_mount,load1,alerts" ] && [ "$(wc -l < /tmp/cs/logs/metrics.csv)" -eq 2 ]'
"${ME[@]}" "$M" > /dev/null 2>&1
check M4 "Second run appends exactly one more row (no second header)" '[ "$(wc -l < /tmp/cs/logs/metrics.csv)" -eq 3 ]'
( for i in 1 2 3; do timeout 6 bash -c 'while :; do :; done' & done; wait ) & sleep 1
t M5 "CPU alert under real CPU load (exit 5)" 5 "\[ALERT\] monitor.sh: CPU usage is" "${ME[@]}" CPU_LIMIT=20 "$M"
wait
t M6 "Memory alert (limit 1%)" 5 "Memory usage is" "${ME[@]}" MEM_LIMIT=1 "$M"
t M7 "Disk alert (limit 1%)" 5 "Disk .* is [0-9]+% full" "${ME[@]}" DISK_LIMIT=1 "$M"
t M8 "SELinux Permissive raises an alert" 5 "SELinux mode is Permissive" "${ME[@]}" STUB_SELINUX=Permissive "$M"
t M9 "SELinux check can be switched off" 0 "All checks passed" "${ME[@]}" STUB_SELINUX=Disabled CHECK_SELINUX=no "$M"
t M10 "Service down raises alert" 5 "Service ssh is not running" "${ME[@]}" SERVICES=ssh STUB_DOWN=ssh "$M"
t M11 "Missing service skipped, not an alert" 0 "not installed on this host, skipped" "${ME[@]}" SERVICES=ufw STUB_MISSING=ufw "$M"
t M12 "EXTRA_SERVICES (nginx) checked" 5 "Service nginx is not running" "${ME[@]}" SERVICES=sshd EXTRA_SERVICES=nginx STUB_DOWN=nginx "$M"
printf 'ID="rhel"\nID_LIKE="fedora"\n' > "$T/os-rhel"
t M13 "RHEL detected: firewalld, chronyd and crond are checked" 0 "Service firewalld: running" "${ME[@]}" OS_RELEASE="$T/os-rhel" "$M"
t M14 "RHEL default list includes crond and chronyd" 0 "Service crond: running" "${ME[@]}" OS_RELEASE="$T/os-rhel" "$M"
t M15 "RHEL: firewalld stopped is an alert" 5 "Service firewalld is not running" "${ME[@]}" OS_RELEASE="$T/os-rhel" STUB_DOWN=firewalld "$M"
t M16 "Non-numeric limit refused" 2 "CPU_LIMIT must be" "${ME[@]}" CPU_LIMIT=abc "$M"
t M17 "Limit above 100 refused" 2 "MEM_LIMIT must be" "${ME[@]}" MEM_LIMIT=150 "$M"
t M18 "Not root refused" 4 "Run this script as root" su -s /bin/bash nobody -c "$M"
( flock 9; sleep 6 ) 9> "$T/monitor.lock" & sleep 1
t M19 "Second instance while one runs" 6 "already running" "${ME[@]}" "$M"
wait
t M20 "Unwritable log: warning, still works" 0 "cannot write .*syslog only" "${ME[@]}" LOG_FILE=/proc/nope/x.log "$M"
out=$("${ME[@]}" "$M" -q 2>&1); echo "$out" > "$T/evidence/M21.txt"
if [ -z "$out" ]; then PASS=$((PASS+1)); echo "M21   PASS --quiet prints nothing when all is well"; printf 'M21\t--quiet prints nothing when all is well\toutput empty\toutput empty\tPASS\n' >> "$T/results.tsv"; else FAIL=$((FAIL+1)); echo "M21   FAIL --quiet printed output"; printf 'M21\t--quiet prints nothing when all is well\toutput empty\tprinted\tFAIL\n' >> "$T/results.tsv"; fi
rm -f "$T/mail.out" "$T"/state/*
t M22 "E-mail alert sent" 5 "Memory usage" "${ME[@]}" MEM_LIMIT=1 ALERT_EMAIL=soc@example.com "$M"
"${ME[@]}" MEM_LIMIT=1 ALERT_EMAIL=soc@example.com "$M" > /dev/null 2>&1
check M23 "E-mail cooldown: 2 runs sent exactly 1 mail" '[ "$(wc -l < /tmp/cs/mail.out)" -eq 1 ]'
CM=$(mkconf m.conf $'CPU_LIMIT=100\nMEM_LIMIT=1\nDISK_LIMIT=100\nLOAD_FACTOR=1000')
t M24 "Thresholds read from the config file" 5 "limit 1%" env PATH="$SP" LOG_FILE="$T/logs/monitor.log" METRICS_CSV="$T/logs/metrics.csv" LOCK_FILE="$T/monitor.lock" CS_CONF="$CM" "$M"
( for i in 1 2 3 4; do timeout 40 bash -c 'while :; do :; done' & done; wait ) &
for i in $(seq 1 30); do awk '{exit !($1 > 0.3)}' /proc/loadavg && break; sleep 1; done
if awk '{exit !($1 > 0.3)}' /proc/loadavg; then
  t M25 "Load alert (cores stubbed to 0, real load > 0)" 5 "Load average" "${ME[@]}" PATH="$T/stubs_nproc:$SP" "$M"
else skip M25 "Load alert" "sandbox load average did not rise"; fi
pkill -f 'while :; do :; done' 2>/dev/null; wait 2>/dev/null

#==================== LOG ANALYZER =====================
echo "== log_analyzer.sh =="
L="$T/bin/log_analyzer.sh"
sysl() { printf '%s h sshd[1]: Failed password for root from %s port 22 ssh2\n' "$(date -d "-$1 minutes" '+%b %e %H:%M:%S')" "$2"; }
invl() { printf '%s h sshd[1]: Invalid user oracle from %s port 22\n' "$(date -d "-$1 minutes" '+%b %e %H:%M:%S')" "$2"; }
isol() { printf '%s h sshd[1]: Failed password for invalid user admin from %s port 22 ssh2\n' "$(date -d "-$1 minutes" '+%Y-%m-%dT%H:%M:%S.000000+00:00')" "$2"; }
ngx() { printf '%s - - [%s +0000] "GET / HTTP/1.1" %s 512 "-" "curl"\n' "$2" "$(date -d "-$1 minutes" '+%d/%b/%Y:%H:%M:%S')" "$3"; }
rep() { local n=$1; shift; for _ in $(seq 1 "$n"); do "$@"; done; }
LE=(env PATH="$SP" ACCESS_LOG="$T/logsrc/access.log" SECURE_LOG="$T/logsrc/secure" REPORT_DIR="$T/reports" LOG_FILE="$T/logs/la.log" LOCK_FILE="$T/la.lock" CS_CONF=/nonexistent)
: > "$T/logsrc/access.log"; sysl 5 192.0.2.1 > "$T/logsrc/secure"
t L1 "Clean logs: no alert" 0 "Alerts raised: 0" "${LE[@]}" "$L"
rep 6 sysl 5 198.51.100.7 > "$T/logsrc/secure"
t L2 "6 failures from one IP -> alert, exit 5" 5 "brute force attack from 198.51.100.7 \(6 failed" "${LE[@]}" "$L"
{ rep 4 sysl 5 192.0.2.1; rep 4 sysl 5 192.0.2.2; rep 4 sysl 5 192.0.2.3; } > "$T/logsrc/secure"
t L3 "12 failures spread over 3 IPs, each below limit" 0 "Total failed passwords: 12" "${LE[@]}" "$L"
rep 4 sysl 5 192.0.2.9 > "$T/logsrc/secure"
t L4 "Boundary: limit minus 1 (4) -> no alert" 0 "Alerts raised: 0" "${LE[@]}" "$L"
rep 5 sysl 5 192.0.2.9 > "$T/logsrc/secure"
t L5 "Boundary: exactly the limit (5) -> alert" 5 "192.0.2.9 \(5 failed" "${LE[@]}" "$L"
rep 10 sysl 300 203.0.113.50 > "$T/logsrc/secure"
t L6 "Old failures (5 h ago) outside the 60 min window" 0 "Alerts raised: 0" "${LE[@]}" "$L"
t L7 "-w 0 (whole log) sees them" 5 "203.0.113.50 \(10" "${LE[@]}" "$L" -w 0
t L8 "-w 600 sees them" 5 "203.0.113.50" "${LE[@]}" "$L" -w 600
rep 6 isol 3 198.51.100.8 > "$T/logsrc/secure"
t L9 "Ubuntu ISO timestamps understood" 5 "198.51.100.8 \(6" "${LE[@]}" "$L"
rep 5 sysl 2 2001:db8::5 > "$T/logsrc/secure"
t L10 "IPv6 source address kept whole" 5 "2001:db8::5 \(5" "${LE[@]}" "$L"
rep 6 invl 2 198.51.100.40 > "$T/logsrc/secure"
t L11 "Invalid-user attempts alone trigger an alert (key-only SSH)" 5 "198.51.100.40 \(0 failed logins, 6 invalid" "${LE[@]}" "$L"
{ rep 3 sysl 2 198.51.100.41; rep 2 invl 2 198.51.100.41; } > "$T/logsrc/secure"
t L12 "Failed and invalid-user counts are kept separate" 0 "198.51.100.41 +3 +2" "${LE[@]}" "$L"
{ echo "garbage"; echo ""; echo "Oct 99 99:99:99 broken"; sysl 5 192.0.2.77; } > "$T/logsrc/secure"
t L13 "Malformed lines skipped, no crash" 0 "Lines skipped" "${LE[@]}" "$L"
: > "$T/logsrc/secure"
t L14 "Empty log files" 0 "Alerts raised: 0" "${LE[@]}" "$L"
t L15 "Missing SSH log -> exit 3" 3 "cannot read" "${LE[@]}" SECURE_LOG="$T/logsrc/missing" "$L"
t L16 "Missing access log -> exit 3" 3 "cannot read" "${LE[@]}" ACCESS_LOG="$T/logsrc/missing" "$L"
rep 120 ngx 5 198.51.100.20 404 > "$T/logsrc/access.log"
t L17 "120 HTTP 404 errors -> alert" 5 "Too many HTTP errors: 120" "${LE[@]}" "$L"
rep 99 ngx 5 198.51.100.20 500 > "$T/logsrc/access.log"
t L18 "Boundary: 99 errors (limit 100) -> no alert" 0 "HTTP 4xx/5xx errors: 99" "${LE[@]}" "$L"
{ rep 3 ngx 5 198.51.100.1 200; rep 2 ngx 5 198.51.100.2 200; ngx 5 198.51.100.3 301; } > "$T/logsrc/access.log"
t L19 "Top client IPs shown" 0 "198.51.100.1 : 3 requests" "${LE[@]}" "$L"
rm -f "$T"/reports/*; "${LE[@]}" "$L" > /dev/null 2>&1
check L20 "Report saved in the report folder with the top-IP list" 'ls /tmp/cs/reports/report_*.txt >/dev/null && grep -q "198.51.100.1 : 3 requests" /tmp/cs/reports/report_*.txt'
touch -d "40 days ago" "$T/reports/report_OLD.txt"
"${LE[@]}" "$L" > /dev/null 2>&1
check L21 "Reports older than 30 days are deleted" '[ ! -e /tmp/cs/reports/report_OLD.txt ]'
rep 120 ngx 400 198.51.100.20 404 > "$T/logsrc/access.log"
t L22 "Old HTTP errors outside window ignored" 0 "HTTP 4xx/5xx errors: 0" "${LE[@]}" "$L"
: > "$T/logsrc/access.log"; : > "$T/logsrc/secure"
rep 6 sysl 5 198.51.100.50 > "$T/logsrc/secure.1"
rep 6 sysl 5 198.51.100.51 > "$T/logsrc/secure-20261011"
rep 6 sysl 5 198.51.100.52 | gzip > "$T/logsrc/secure.2.gz"
t L23 "Without -r rotated files are ignored" 0 "Alerts raised: 0" "${LE[@]}" "$L"
t L24 "-r reads secure.1, secure-DATE and secure.2.gz" 5 "198.51.100.50.*198.51.100.51|198.51.100.5[0-2]" "${LE[@]}" "$L" -r
check L25 "-r counted each rotated file once (3 alerts, not 6)" '[ "$(grep -c "Possible brute force" /tmp/cs/evidence/L24.txt)" -eq 3 ]'
rm -f "$T"/logsrc/secure.* "$T"/logsrc/secure-*
rep 6 sysl 5 198.51.100.60 > "$T/logsrc/journal.txt"
t L26 "--journal reads sshd events from journalctl" 5 "198.51.100.60 \(6" "${LE[@]}" "$L" --journal
rm -f "$T/mail.out"; rep 6 sysl 5 198.51.100.7 > "$T/logsrc/secure"
t L27 "Alert e-mailed when ALERT_EMAIL is set" 5 "brute force" "${LE[@]}" ALERT_EMAIL=soc@example.com "$L"
check L28 "Mail stub received the alert text" 'grep -q "198.51.100.7" /tmp/cs/mail.out'
t L29 "Non-numeric window refused" 2 "WINDOW_MIN must be" "${LE[@]}" "$L" -w abc
t L30 "Not root refused" 4 "Run this script as root" su -s /bin/bash nobody -c "$L"
( flock 9; sleep 6 ) 9> "$T/la.lock" & sleep 1
t L31 "Second instance while one runs" 6 "already running" "${LE[@]}" "$L"
wait
t L32 "Unwritable report folder: warning, analysis continues" 5 "report goes to the screen only" "${LE[@]}" REPORT_DIR=/proc/nope "$L"
CL=$(mkconf l.conf $'SSH_LIMIT=7')
t L33 "SSH_LIMIT read from config (6 failures < 7 -> no alert)" 0 "Alerts raised: 0" "${LE[@]}" CS_CONF="$CL" "$L"

#==================== USER MANAGEMENT =====================
echo "== user_mgmt.sh =="
U="$T/bin/user_mgmt.sh"
mkdir -p "$T/data/proj" "$T/other" "$T/crit"; echo secret > "$T/data/proj/a.txt"; echo x > "$T/outside.txt"
ln -s "$T/outside.txt" "$T/data/proj/link"; chmod 666 "$T/data/proj/a.txt"; chmod 777 "$T/data/proj"; chmod 750 "$T/crit"
UE=(env PATH="$SP" LOG_FILE="$T/logs/users.log" ARCHIVE_DIR="$T/removed" ALLOWED_BASES="$T/data /home" CRITICAL_DIR="$T/crit" CS_CONF=/nonexistent)
groupdel cs_analysts 2>/dev/null; groupdel cs_staff 2>/dev/null
sed -i '/^tuid0:/d' /etc/passwd /etc/shadow 2>/dev/null
for u in tuser1 tuser2 tuser3 tadmin tnopw fakesvc; do userdel -r $u 2>/dev/null; done
t U1 "Add analyst" 0 "Temporary password: " "${UE[@]}" "$U" add tuser1 analyst
check U2 "User exists, in cs_analysts, home mode 700" 'id tuser1 >/dev/null && id -nG tuser1 | grep -qw cs_analysts && [ "$(stat -c %a /home/tuser1)" = 700 ]'
check U3 "Password must be changed at first login" 'chage -l tuser1 | grep -qi "password must be changed"'
check U4 "Password expiry 90 days" 'chage -l tuser1 | grep -q "Maximum number of days between password change.*90"'
check U5 "Temporary password NOT in the log; action is" '! grep -q "Temporary password" /tmp/cs/logs/users.log && grep -q "\[INFO\] user_mgmt.sh: Created user tuser1" /tmp/cs/logs/users.log'
t U6 "Add admin role (wheel/sudo group)" 0 "Created user tadmin" "${UE[@]}" "$U" add tadmin admin
check U7 "Admin is in wheel or sudo" 'id -nG tadmin | grep -Eqw "sudo|wheel"'
t U8 "Add staff uses cs_staff (not the Debian group 'staff')" 0 "Created user tuser2" "${UE[@]}" "$U" add tuser2 staff
check U9 "tuser2 in cs_staff, not in staff" 'id -nG tuser2 | grep -qw cs_staff && ! id -nG tuser2 | grep -qw staff'
t U10 "Add existing user" 1 "already exists" "${UE[@]}" "$U" add tuser1 analyst
t U11 "Invalid name: capital letter" 2 "Invalid username" "${UE[@]}" "$U" add Admin analyst
t U12 "Invalid name: shell characters" 2 "Invalid username" "${UE[@]}" "$U" add 'bad;name' analyst
t U13 "Invalid name: too short" 2 "Invalid username" "${UE[@]}" "$U" add ab analyst
t U14 "Invalid name: 33 characters" 2 "Invalid username" "${UE[@]}" "$U" add abcdefghijklmnopqrstuvwxyzabcdefg analyst
t U15 "Unknown role" 2 "Unknown role" "${UE[@]}" "$U" add tuser3 hacker
check U16 "Unknown role created no account" '! id tuser3 2>/dev/null'
t U17 "Add without role shows usage" 2 "Usage" "${UE[@]}" "$U" add tuser3
t U18 "Rollback when the password step fails" 1 "removed again" "${UE[@]}" PATH="$T/fail_chpasswd:$SP" "$U" add tuser3 analyst
check U19 "No half-created account left" '! id tuser3 2>/dev/null && [ ! -d /home/tuser3 ]'
t U20 "Dry run add creates nothing" 0 "DRY-RUN: would create user tuser3" "${UE[@]}" "$U" --dry-run add tuser3 analyst
check U21 "Dry run left no account" '! id tuser3 2>/dev/null'
t U22 "Lock dry run" 0 "DRY-RUN: would lock" "${UE[@]}" "$U" -n lock tuser1
check U23 "Dry run did not lock" '! passwd -S tuser1 | awk "{print \$2}" | grep -q "^L"'
t U24 "Lock user" 0 "Locked user tuser1" "${UE[@]}" "$U" lock tuser1
check U25 "Account shows locked" 'passwd -S tuser1 | awk "{print \$2}" | grep -q "^L"'
t U26 "List shows locked state" 0 "tuser1 .*locked" "${UE[@]}" "$U" list
t U27 "Unlock user" 0 "Unlocked user tuser1" "${UE[@]}" "$U" unlock tuser1
check U28 "Account no longer locked" '! passwd -S tuser1 | awk "{print \$2}" | grep -q "^L"'
t U29 "Lock non-existent user" 1 "does not exist" "${UE[@]}" "$U" lock nobodyhere
useradd -r -m -d /home/fakesvc -s /bin/bash fakesvc
t U30 "Remove SYSTEM account refused" 2 "Refusing to change system account" "${UE[@]}" "$U" remove fakesvc -y
check U31 "System account still exists" 'id fakesvc >/dev/null'
t U32 "Lock root refused" 2 "Refusing to change system account" "${UE[@]}" "$U" lock root
t U33 "Lock daemon refused" 2 "Refusing to change system account" "${UE[@]}" "$U" lock daemon
t U34 "Cannot lock your own account (SUDO_USER)" 2 "your own account" "${UE[@]}" SUDO_USER=tuser1 "$U" lock tuser1
t U35 "Remove answered 'n' is cancelled" 0 "cancelled" piped n "${UE[@]}" "$U" remove tuser2
check U36 "Cancelled removal kept the user" 'id tuser2 >/dev/null'
t U37 "Remove dry run changes nothing" 0 "DRY-RUN: would archive" "${UE[@]}" "$U" -n remove tuser2
check U38 "Dry run kept the user" 'id tuser2 >/dev/null'
echo "private-key-data" > /home/tuser2/id_rsa
t U39 "Remove answered 'y' interactively" 0 "Removed user tuser2" piped y "${UE[@]}" "$U" remove tuser2
check U40 "User gone, archive exists" '! id tuser2 2>/dev/null && ls /tmp/cs/removed/tuser2_*.tar.gz >/dev/null'
check U41 "Archive private (file 600, folder 700) and holds the data" '[ "$(stat -c %a /tmp/cs/removed)" = 700 ] && [ "$(stat -c %a /tmp/cs/removed/tuser2_*.tar.gz)" = 600 ] && tar -tzf /tmp/cs/removed/tuser2_*.tar.gz | grep -q id_rsa'
useradd -m tuser3
t U42 "Archive fails (tar broken) -> user NOT removed" 1 "was NOT removed" "${UE[@]}" PATH="$T/fail_tar:$SP" "$U" remove tuser3 -y
check U43 "User still exists" 'id tuser3 >/dev/null && [ -d /home/tuser3 ]'
t U44 "Archive folder cannot be created -> exit 3, user kept" 3 "Cannot create" "${UE[@]}" ARCHIVE_DIR=/proc/nope "$U" remove tuser3 -y
t U45 "Remove with -y non-interactively" 0 "Removed user tuser3" "${UE[@]}" "$U" remove tuser3 -y
t U46 "Remove non-existent user" 1 "does not exist" "${UE[@]}" "$U" remove tuser3 -y
: > "$T/restorecon.log"
t U47 "perms on a project folder" 0 "Set owner tuser1" "${UE[@]}" "$U" perms tuser1 "$T/data/proj"
check U48 "Folder 750, file 640, owner tuser1, files not executable" '[ "$(stat -c %a /tmp/cs/data/proj)" = 750 ] && [ "$(stat -c %a /tmp/cs/data/proj/a.txt)" = 640 ] && [ "$(stat -c %U /tmp/cs/data/proj/a.txt)" = tuser1 ] && [ ! -x /tmp/cs/data/proj/a.txt ]'
check U49 "Symlink target outside the folder NOT changed" '[ "$(stat -c %U /tmp/cs/outside.txt)" = root ]'
check U50 "SELinux label restored after perms (restorecon called)" 'grep -q "restorecon -R -- /tmp/cs/data/proj" /tmp/cs/restorecon.log'
t U51 "perms dry run" 0 "DRY-RUN: would give" "${UE[@]}" "$U" -n perms tuser1 "$T/data/proj"
t U52 "perms on / refused" 2 "Refusing to change /" "${UE[@]}" "$U" perms tuser1 /
t U53 "perms on /etc refused" 2 "Refusing to change /etc" "${UE[@]}" "$U" perms tuser1 /etc
t U54 "perms outside allowed bases refused" 2 "allowed only below" "${UE[@]}" "$U" perms tuser1 "$T/other"
t U55 "Path traversal (..) refused" 2 "Refusing" "${UE[@]}" "$U" perms tuser1 "$T/data/../other"
ln -s /etc "$T/data/escape"
t U56 "Symlink to /etc refused" 2 "Refusing to change /etc" "${UE[@]}" "$U" perms tuser1 "$T/data/escape"
t U57 "perms on missing directory" 1 "does not exist" "${UE[@]}" "$U" perms tuser1 "$T/data/nothere"
t U58 "perms without directory" 2 "Missing" "${UE[@]}" "$U" perms tuser1
t U59 "perms for non-existent user" 1 "does not exist" "${UE[@]}" "$U" perms ghostuser "$T/data/proj"
t U60 "list as root" 0 "tadmin" "${UE[@]}" "$U" list
t U61 "list works without root" 0 "USER" su -s /bin/bash nobody -c "$U list"
t U62 "Not root: add refused" 4 "Run this script as root" su -s /bin/bash nobody -c "$U add tuser3 staff"
t U63 "Not root: audit refused" 4 "Run this script as root" su -s /bin/bash nobody -c "$U audit"
t U64 "Unknown action shows usage" 2 "Usage|Purpose" "${UE[@]}" "$U" explode
t U65 "No arguments shows usage" 2 "Purpose" "${UE[@]}" "$U"
t U66 "PASSWORD_MAX_DAYS from environment (45)" 0 "Created user tuser3" "${UE[@]}" PASSWORD_MAX_DAYS=45 "$U" add tuser3 analyst
check U67 "Expiry is 45 days" 'chage -l tuser3 | grep -q "Maximum number of days between password change.*45"'
userdel -r tuser3 2>/dev/null
# ---- audit ----
for u in tuser1 tadmin; do :; done
t A1 "Audit: clean critical folder (750), no findings in the audited areas" 0 "Audit finished: no findings" "${UE[@]}" "$U" audit
touch "$T/crit/open.txt"; chmod 666 "$T/crit/open.txt"
t A2 "Audit: world-writable file reported, exit 5" 5 "World-writable item: /tmp/cs/crit/open.txt" "${UE[@]}" "$U" audit
rm -f "$T/crit/open.txt"; chmod 777 "$T/crit"
t A3 "Audit: critical folder open to others (777) reported" 5 "accessible to others \(mode 777" "${UE[@]}" "$U" audit
chmod 750 "$T/crit"
useradd -o -u 0 -N -M tuid0 2>/dev/null
t A4 "Audit: extra UID 0 account reported" 5 "'tuid0' has UID 0" "${UE[@]}" "$U" audit
sed -i '/^tuid0:/d' /etc/passwd /etc/shadow; rm -rf /home/tuid0
useradd -m tnopw; passwd -d tnopw >/dev/null 2>&1
t A5 "Audit: account with empty password reported" 5 "'tnopw' has an EMPTY password" "${UE[@]}" "$U" audit
userdel -r tnopw 2>/dev/null
t A6 "Audit: missing critical folder is a warning, not a finding" 0 "does not exist on this host, skipped" "${UE[@]}" CRITICAL_DIR="$T/nothere" "$U" audit
t A7 "Audit: shows normal accounts and admin group members" 0 "=== 2. Members of the administrator group" "${UE[@]}" "$U" audit
CU=$(mkconf u.conf $'PASSWORD_MAX_DAYS=30\nARCHIVE_DIR=/tmp/cs/removed2')
t U68 "Settings read from the config file (30-day expiry)" 0 "Created user tuser3" env PATH="$SP" LOG_FILE="$T/logs/users.log" ALLOWED_BASES="$T/data /home" CS_CONF="$CU" "$U" add tuser3 analyst
check U69 "Config value applied" 'chage -l tuser3 | grep -q "Maximum number of days between password change.*30"'
sed -i '/^tuid0:/d' /etc/passwd /etc/shadow 2>/dev/null
for u in tuser1 tuser2 tuser3 tadmin tnopw fakesvc; do userdel -r $u 2>/dev/null; done; groupdel cs_analysts 2>/dev/null; groupdel cs_staff 2>/dev/null

echo
echo "TOTAL: $((PASS+FAIL+SKIP)) tests  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
cp "$T/results.tsv" "$SRC/tests/results.tsv" 2>/dev/null || cp "$T/results.tsv" "$SRC/test_results.tsv" 2>/dev/null || true
[ "$FAIL" -eq 0 ]
