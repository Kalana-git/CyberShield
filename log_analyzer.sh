#!/usr/bin/bash
#==============================================================================
# log_analyzer.sh - Log file analysis and alerting for CyberShield Solutions
#------------------------------------------------------------------------------
# Version  : 2.0.0     Author: Kalana Supasan - COMP2000 Assignment 2026
# Run on   : WEB-01 / WEB-02, as root
# Purpose  : Read the SSH log and the Nginx access log, count failed logins and
#            invalid-user attempts per source IP and HTTP 4xx/5xx errors inside
#            a time window, save a report and alert on suspicious activity.
# Usage    : log_analyzer.sh [options]
#              -w, --window MIN    look back MIN minutes (default 60, 0 = all)
#              -r, --include-rotated  also read rotated and compressed logs
#                                  (secure-DATE, secure.1, secure.2.gz ...)
#                  --journal       read SSH events from journalctl instead of
#                                  /var/log/secure
#              -c, --config FILE   settings file (default
#                                  /etc/cybershield/cybershield.conf)
#              -h, --help          show this help
#              -V, --version       show the version
# Settings : KEY=value lines in the config file or environment variables:
#            ACCESS_LOG SECURE_LOG SSH_LIMIT ERROR_LIMIT WINDOW_MIN
#            REPORT_DIR REPORT_KEEP_DAYS ALERT_EMAIL LOG_FILE LOCK_FILE
# Logs     : SSH: /var/log/secure (RHEL, chosen automatically) or
#            /var/log/auth.log (Ubuntu). Web: /var/log/nginx/access.log.
# Cron     : 0 * * * * root /opt/cybershield/log_analyzer.sh -q (/etc/cron.d)
# Needs    : bash 4.4+, gawk, gzip (zcat), coreutils, findutils, util-linux
#            (flock), systemd (journalctl, only for --journal); s-nail/mailx
#            only for e-mail alerts
# Exit     : 0 clean | 2 bad option or setting | 3 a log is missing or
#            unreadable | 4 not root | 5 alerts raised | 6 already running
#==============================================================================

set -Eeuo pipefail

# ----- Common helpers (identical in all four CyberShield scripts) ------------
readonly SCRIPT_NAME="${0##*/}"
# shellcheck disable=SC2034  # not every script uses every constant
readonly VERSION="2.0.0" EX_FAIL=1 EX_USAGE=2 EX_PREREQ=3 EX_PRIV=4 EX_ALERT=5 EX_LOCKED=6
QUIET=0
CLEANUP_FILES=()

# Print the header comment block of this script as help text
usage() {
    sed -n '2,/^#=====/p' "$0" | sed '1d;$d;s/^# \{0,1\}//'
}

# log LEVEL MESSAGE... : timestamp + level + script name to screen, log file
# and syslog/journal. ERROR, WARN and ALERT go to STDERR (RH134 ch.1 practice).
log() {
    local level=$1 prio line
    shift
    case $level in
        ERROR) prio=err ;;
        WARN)  prio=warning ;;
        ALERT) prio=crit ;;
        *)     prio=info ;;
    esac
    line="$(date '+%Y-%m-%d %H:%M:%S') [$level] $SCRIPT_NAME: $*"
    if [[ $level == ERROR || $level == WARN || $level == ALERT ]]; then
        printf '%s\n' "$line" >&2
    elif (( ! QUIET )); then
        printf '%s\n' "$line"
    fi
    printf '%s\n' "$line" >>"${LOG_FILE:-/dev/null}" 2>/dev/null || true
    logger -t "cybershield-${SCRIPT_NAME%.sh}" -p "user.$prio" -- "$*" 2>/dev/null || true
}

# die CODE MESSAGE... : log an error and leave with the given exit code
die() {
    local code=$1
    shift
    log ERROR "$*"
    exit "$code"
}

# ERR trap: report an unexpected command failure with its line number and
# leave with exit code 1 (the code of the failed command could be misread)
on_err() {
    log ERROR "Unexpected failure (exit $1) at line $2"
    exit "$EX_FAIL"
}

# EXIT trap: remove temporary and unfinished files, whatever the exit reason
cleanup() {
    local f
    for f in "${CLEANUP_FILES[@]:-}"; do
        if [[ -n $f ]]; then rm -rf -- "$f"; fi
    done
}
trap 'on_err $? $LINENO' ERR
trap cleanup EXIT
trap 'log ERROR "Interrupted"; exit 1' INT TERM

# require_cmd CMD... : stop (exit 3) when a needed program is missing
require_cmd() {
    local c
    for c in "$@"; do
        if ! command -v "$c" >/dev/null 2>&1; then
            die "$EX_PREREQ" "Required command not found: $c"
        fi
    done
}

# require_root : stop (exit 4) unless running as root
require_root() {
    if (( EUID != 0 )); then
        echo "Run this script as root (use sudo)" >&2
        exit "$EX_PRIV"
    fi
}

# validate_int NAME VALUE MIN MAX : whole number in a range, else exit 2
validate_int() {
    if [[ ! $2 =~ ^[0-9]+$ ]] || (( $2 < $3 || $2 > $4 )); then
        die "$EX_USAGE" "$1 must be a whole number from $3 to $4 (got '$2')"
    fi
}

# find_config_arg "$@" : pick up -c/--config FILE before the config is loaded
find_config_arg() {
    local prev="" a
    for a in "$@"; do
        if [[ $prev == -c || $prev == --config ]]; then CONF_FILE=$a; fi
        prev=$a
    done
}

# load_config FILE KEY... : read KEY=value lines for the listed keys only.
# The file is parsed, never executed, so it cannot run commands. It must be
# owned by root and not writable by group/others. Values that are already set
# in the environment win over the file; command-line options win over both.
load_config() {
    local f=$1 line key val k ok owner mode
    shift
    [[ -f $f ]] || return 0
    owner=$(stat -c %u -- "$f")
    mode=$(stat -c %a -- "$f")
    if [[ $owner != 0 ]] || (( 8#$mode & 8#022 )); then
        echo "ERROR: refusing to read $f (must be owned by root, not group/other-writable)" >&2
        exit "$EX_PREREQ"
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ ^[[:space:]]*(#.*)?$ ]]; then continue; fi
        if [[ $line =~ ^[[:space:]]*([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
            key=${BASH_REMATCH[1]}
            val=${BASH_REMATCH[2]}
            val=${val%\"}; val=${val#\"}; val=${val%\'}; val=${val#\'}
            ok=0
            for k in "$@"; do
                if [[ $k == "$key" ]]; then ok=1; fi
            done
            if (( ok )); then
                if [[ ! -v $key ]]; then printf -v "$key" '%s' "$val"; fi
            else
                echo "WARN: ignoring unknown setting '$key' in $f" >&2
            fi
        else
            echo "WARN: ignoring unreadable line in $f: $line" >&2
        fi
    done <"$f"
}

# fix_selinux_context PATH : restore the default SELinux label (RH134 ch.4:
# restorecon) when SELinux is active; silently does nothing elsewhere
fix_selinux_context() {
    if command -v restorecon >/dev/null 2>&1 && command -v selinuxenabled >/dev/null 2>&1 \
        && selinuxenabled; then
        restorecon -R -- "$1" 2>/dev/null || log WARN "restorecon failed for $1"
    fi
}

# init_logging : create the log folder (mode 750) and make sure the log can be
# written; otherwise continue with screen and syslog only
init_logging() {
    local dir
    dir=$(dirname -- "$LOG_FILE")
    if [[ ! -d $dir ]]; then
        # shellcheck disable=SC2174  # only the log folder itself needs mode 750
        mkdir -p -m 0750 -- "$dir" 2>/dev/null || true
        fix_selinux_context "$dir"
    fi
    if ! ( umask 027; touch -- "$LOG_FILE" ) 2>/dev/null; then
        echo "WARNING: cannot write $LOG_FILE, logging to screen and syslog only" >&2
        LOG_FILE=/dev/null
    fi
}

# acquire_lock : one running copy per script (flock on file descriptor 9);
# non-root users get a lock file in /tmp so they can still run the script
acquire_lock() {
    # the braces keep "2>/dev/null" from becoming a permanent redirection of exec
    if ! { exec 9>"$LOCK_FILE"; } 2>/dev/null; then
        LOCK_FILE="${TMPDIR:-/tmp}/cybershield-${SCRIPT_NAME%.sh}-${UID}.lock"
        exec 9>"$LOCK_FILE" || die "$EX_PREREQ" "Cannot open a lock file"
    fi
    if ! flock -n 9; then
        die "$EX_LOCKED" "Another $SCRIPT_NAME is already running"
    fi
}

# ----- Settings --------------------------------------------------------------
CONF_FILE="${CS_CONF:-/etc/cybershield/cybershield.conf}"
CONFIG_KEYS=(ACCESS_LOG SECURE_LOG SSH_LIMIT ERROR_LIMIT WINDOW_MIN REPORT_DIR
             REPORT_KEEP_DAYS ALERT_EMAIL LOG_FILE LOCK_FILE)
INCLUDE_ROTATED=no
USE_JOURNAL=no
ALERTS=0
LOG_PROBLEMS=0
ALERT_TEXT=""
CUTOFF=""
REPORT_FILE=/dev/null

apply_defaults() {
    ACCESS_LOG="${ACCESS_LOG:-/var/log/nginx/access.log}"
    SECURE_LOG="${SECURE_LOG:-}"
    SSH_LIMIT="${SSH_LIMIT:-5}"
    ERROR_LIMIT="${ERROR_LIMIT:-100}"
    WINDOW_MIN="${WINDOW_MIN:-60}"
    REPORT_DIR="${REPORT_DIR:-/var/log/cybershield/reports}"
    REPORT_KEEP_DAYS="${REPORT_KEEP_DAYS:-30}"
    ALERT_EMAIL="${ALERT_EMAIL:-}"
    LOG_FILE="${LOG_FILE:-/var/log/cybershield/log_analyzer.log}"
    LOCK_FILE="${LOCK_FILE:-/run/lock/cybershield-log_analyzer.lock}"
}

parse_args() {
    while (( $# )); do
        case $1 in
            -w|--window)           WINDOW_MIN=${2:?-w needs a number of minutes}; shift 2 ;;
            -r|--include-rotated)  INCLUDE_ROTATED=yes; shift ;;
            --journal)             USE_JOURNAL=yes; shift ;;
            -q|--quiet)            QUIET=1; shift ;;
            -c|--config)           shift 2 ;;
            -h|--help)             usage; exit 0 ;;
            -V|--version)          echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
            *)                     echo "Unknown option: $1" >&2; usage >&2; exit "$EX_USAGE" ;;
        esac
    done
}

# awk helpers shared by both log types: dates -> seconds, month names, window
# shellcheck disable=SC2016  # awk code must stay in single quotes
AWK_LIB='
function dfc(y, m, d,   era, yoe, doy, doe) {       # days since 1970-01-01
    y -= (m <= 2)
    era = int((y >= 0 ? y : y - 399) / 400)
    yoe = y - era * 400
    doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
    return era * 146097 + doe - 719468
}
function epoch(y, m, d, H, M, S) { return dfc(y, m, d) * 86400 + H * 3600 + M * 60 + S }
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", names, " ")
    for (i = 1; i <= 12; i++) mon[names[i]] = i
    split(now_s, n, " ");  cur_year = n[1] + 0
    now_ts = epoch(n[1] + 0, n[2] + 0, n[3] + 0, n[4] + 0, n[5] + 0, n[6] + 0)
    cutoff = 0
    if (cutoff_s != "") {
        split(cutoff_s, c, " ")
        cutoff = epoch(c[1] + 0, c[2] + 0, c[3] + 0, c[4] + 0, c[5] + 0, c[6] + 0)
    }
}
# SSH time: "2026-10-12T10:15:01+05:30 host ..." or "Oct 12 10:15:01 host ..."
function ssh_ts(   a, t, ts) {
    if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) {
        split(substr($1, 1, 19), a, /[-T:]/)
        return epoch(a[1] + 0, a[2] + 0, a[3] + 0, a[4] + 0, a[5] + 0, a[6] + 0)
    }
    if (($1 in mon) && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) {
        split($3, t, ":")
        ts = epoch(cur_year, mon[$1], $2 + 0, t[1] + 0, t[2] + 0, t[3] + 0)
        if (ts > now_ts + 86400)                      # December log read in January
            ts = epoch(cur_year - 1, mon[$1], $2 + 0, t[1] + 0, t[2] + 0, t[3] + 0)
        return ts
    }
    return -1
}
# Nginx time: "[12/Oct/2026:10:15:01 +0530]" is field 4
function web_ts(   a) {
    if (substr($4, 1, 1) != "[") return -1
    split(substr($4, 2), a, /[\/:]/)
    if (!(a[2] in mon)) return -1
    return epoch(a[3] + 0, mon[a[2]], a[1] + 0, a[4] + 0, a[5] + 0, a[6] + 0)
}'

# ----- Functions -------------------------------------------------------------

# Print to the screen and to the report file
say() {
    if (( ! QUIET )); then printf '%s\n' "$1"; fi
    printf '%s\n' "$1" >>"$REPORT_FILE"
}

# Count the alert, show it, log it (journal) and remember it for the e-mail
send_alert() {
    ALERTS=$((ALERTS + 1))
    ALERT_TEXT="${ALERT_TEXT}${1}"$'\n'
    log ALERT "$1"
    printf 'ALERT: %s\n' "$1" >>"$REPORT_FILE"
}

# A log that cannot be read means blind monitoring: count it
check_file() {
    if [[ ! -f $1 || ! -r $1 ]]; then
        say "ERROR: cannot read $1"
        log ERROR "Cannot read $1"
        LOG_PROBLEMS=$((LOG_PROBLEMS + 1))
        return 1
    fi
    return 0
}

# Create the report file in REPORT_DIR and delete old reports
init_report() {
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    if [[ ! -d $REPORT_DIR ]]; then
        # shellcheck disable=SC2174  # only the report folder itself needs mode 750
        mkdir -p -m 0750 -- "$REPORT_DIR" 2>/dev/null || true
        fix_selinux_context "$REPORT_DIR"
    fi
    REPORT_FILE="$REPORT_DIR/report_${ts}.txt"
    if ! ( umask 027; : >"$REPORT_FILE" ) 2>/dev/null; then
        log WARN "Cannot write to $REPORT_DIR, the report goes to the screen only"
        REPORT_FILE=/dev/null
    else
        find "$REPORT_DIR" -maxdepth 1 -type f -name 'report_*.txt' -mtime +"$REPORT_KEEP_DAYS" -delete 2>/dev/null || true
    fi
}

# SSH log of this OS: /var/log/secure (RHEL) or /var/log/auth.log (Ubuntu)
detect_secure_log() {
    if [[ -n $SECURE_LOG ]]; then return 0; fi
    if [[ -r /var/log/secure ]]; then
        SECURE_LOG=/var/log/secure
    else
        SECURE_LOG=/var/log/auth.log
    fi
}

# Rotated copies: RHEL date-stamped (secure-20261011), numbered, compressed
rotated_files() {
    local f
    for f in "$SECURE_LOG"-* "$SECURE_LOG".[0-9]* "$SECURE_LOG"*.gz; do
        if [[ -f $f && -r $f && $f != "$SECURE_LOG" ]]; then echo "$f"; fi
    done | sort -u
}

# ssh_source : stream the SSH events (zcat -f also reads plain files)
ssh_source() {
    local f
    if [[ $USE_JOURNAL == yes ]]; then
        if (( WINDOW_MIN > 0 )); then
            journalctl _COMM=sshd -o short --no-pager --since "${WINDOW_MIN} minutes ago"
        else
            journalctl _COMM=sshd -o short --no-pager
        fi
        return 0
    fi
    zcat -f -- "$SECURE_LOG"
    if [[ $INCLUDE_ROTATED == yes ]]; then
        while IFS= read -r f; do zcat -f -- "$f"; done < <(rotated_files)
    fi
}

# run_awk PROGRAM : run awk on stdin with the shared helpers
run_awk() {
    awk -v cutoff_s="$CUTOFF" -v now_s="$(date '+%Y %m %d %H %M %S')" "$AWK_LIB $1"
}

# Web traffic: total requests, top IPs and error counts inside the window
analyze_web() {
    local kind a b total=0 errors=0 bad=0 top="" count ip
    say "--- Web traffic from $ACCESS_LOG (last ${WINDOW_MIN} min, 0 = whole log) ---"
    if [[ -z $ACCESS_LOG || ! -e $ACCESS_LOG ]]; then
        say "(Nginx access log not found, skipped)"
        return 0
    fi
    if ! check_file "$ACCESS_LOG"; then return 0; fi
    while read -r kind a b; do
        case $kind in
            TOTAL) total=$a ;;
            ERR)   errors=$a ;;
            BAD)   bad=$a ;;
            IP)    top+="$a $b"$'\n' ;;
        esac
    done < <(run_awk '
        { ts = web_ts(); if (ts < 0) { bad++; next }
          if (cutoff > 0 && ts < cutoff) next
          total++; ip[$1]++
          if ($9 ~ /^[45][0-9][0-9]$/) err++ }
        END { print "TOTAL", total + 0; print "ERR", err + 0; print "BAD", bad + 0
              for (i in ip) print "IP", ip[i], i }' <"$ACCESS_LOG")
    say "Total requests: $total"
    say "Top 3 client IPs:"
    if [[ -n $top ]]; then
        while read -r count ip; do
            say "  $ip : $count requests"
        done < <(printf '%s' "$top" | sort -rn | head -3)
    fi
    say "HTTP 4xx/5xx errors: $errors"
    if (( bad > 0 )); then say "Lines skipped (unreadable format): $bad"; fi
    if (( errors >= ERROR_LIMIT )); then
        send_alert "Too many HTTP errors: $errors (limit $ERROR_LIMIT)"
    fi
}

# SSH: failed passwords and invalid-user attempts per source IP (IPv4 + IPv6)
analyze_ssh() {
    local kind a b c total=0 invalid=0 bad=0 list="" line fails inv ip
    say "--- SSH logins from ${SECURE_LOG} (last ${WINDOW_MIN} min, 0 = whole log) ---"
    if [[ $USE_JOURNAL == yes ]]; then
        say "(source: journalctl _COMM=sshd)"
    elif ! check_file "$SECURE_LOG"; then
        return 0
    fi
    while read -r kind a b c; do
        case $kind in
            TOTAL) total=$a; invalid=$b ;;
            BAD)   bad=$a ;;
            IP)    list+="$a $b $c"$'\n' ;;       # "failed invalid ip"
        esac
    done < <(ssh_source | run_awk '
        { ts = ssh_ts(); if (ts < 0) { bad++; next }
          if (cutoff > 0 && ts < cutoff) next
          if ($0 !~ /sshd/) next
          isfail = ($0 ~ /Failed password/)
          isinv  = ($0 ~ /Invalid user/ && $0 !~ /Failed password/)
          if (!isfail && !isinv) next
          if (match($0, / from [0-9A-Fa-f:.]+ port /)) {
              ip = substr($0, RSTART + 6, RLENGTH - 12); seen[ip] = 1
              if (isfail) { fail[ip]++; tf++ } else { inv[ip]++; ti++ }
          } else bad++ }
        END { print "TOTAL", tf + 0, ti + 0; print "BAD", bad + 0
              for (ip in seen) print "IP", fail[ip] + 0, inv[ip] + 0, ip }')
    say "Total failed passwords: $total   invalid-user attempts: $invalid"
    if (( bad > 0 )); then say "Lines skipped (unreadable format): $bad"; fi
    if [[ -z $list ]]; then return 0; fi
    say "  Source IP                                  Failed  Invalid-user"
    while read -r fails inv ip; do
        printf -v line '  %-40s %7s %12s' "$ip" "$fails" "$inv"
        say "$line"
    done < <(printf '%s' "$list" | sort -k1,1nr -k2,2nr)
    # a second loop (not inside the one above) keeps the ALERTS counter correct
    while read -r fails inv ip; do
        if (( fails >= SSH_LIMIT || inv >= SSH_LIMIT )); then
            send_alert "Possible brute force attack from $ip ($fails failed logins, $inv invalid-user attempts)"
        fi
    done < <(printf '%s' "$list" | sort -k1,1nr -k2,2nr)
}

# E-mail the alerts when ALERT_EMAIL is set
email_alerts() {
    if [[ -z $ALERT_EMAIL ]]; then return 0; fi
    if ! command -v mail >/dev/null 2>&1; then
        log WARN "'mail' is not installed, cannot e-mail the alerts"
        return 0
    fi
    printf '%s' "$ALERT_TEXT" | mail -s "[CyberShield] $ALERTS log alert(s) on $(hostname -s)" "$ALERT_EMAIL" \
        || log WARN "Could not e-mail the alerts to $ALERT_EMAIL"
}

# ----- Main ------------------------------------------------------------------
main() {
    find_config_arg "$@"
    load_config "$CONF_FILE" "${CONFIG_KEYS[@]}"
    apply_defaults
    parse_args "$@"
    require_root
    init_logging
    require_cmd awk zcat sort date find flock
    if [[ $USE_JOURNAL == yes ]]; then require_cmd journalctl; fi
    validate_int WINDOW_MIN "$WINDOW_MIN" 0 5256000
    validate_int SSH_LIMIT "$SSH_LIMIT" 1 1000000
    validate_int ERROR_LIMIT "$ERROR_LIMIT" 1 1000000
    validate_int REPORT_KEEP_DAYS "$REPORT_KEEP_DAYS" 1 3650
    acquire_lock

    if (( WINDOW_MIN > 0 )); then
        CUTOFF=$(date -d "-${WINDOW_MIN} minutes" '+%Y %m %d %H %M %S')
    fi
    detect_secure_log
    init_report

    say "===== Log report $(date '+%F %T') on $(hostname -s) ====="
    analyze_web
    analyze_ssh
    say "Alerts raised: $ALERTS"
    if [[ $REPORT_FILE != /dev/null ]]; then log INFO "Report saved: $REPORT_FILE"; fi

    if (( ALERTS > 0 )); then
        email_alerts
        exit "$EX_ALERT"
    fi
    if (( LOG_PROBLEMS > 0 )); then exit "$EX_PREREQ"; fi
    log INFO "No suspicious activity found"
}

main "$@"
