#!/usr/bin/bash
#==============================================================================
# monitor.sh - System performance and resource monitor (RHEL 9 / Ubuntu 24.04)
#------------------------------------------------------------------------------
# Version  : 2.0.0     Author: Kalana Supasan - COMP2000 Assignment 2026
# Run on   : every CyberShield server, as root
# Purpose  : Check CPU, memory, every mounted disk, load average, the SELinux
#            mode and key services. Write the readings to a log and a CSV file
#            and raise alerts (journal + optional e-mail with cooldown).
# Usage    : monitor.sh [options]
#              -q, --quiet        no screen output except alerts (for cron)
#              -c, --config FILE  settings file (default
#                                 /etc/cybershield/cybershield.conf)
#              -h, --help         show this help
#              -V, --version      show the version
# Settings : KEY=value lines in the config file or environment variables:
#            CPU_LIMIT MEM_LIMIT DISK_LIMIT LOAD_FACTOR SAMPLE_SECONDS
#            SERVICES EXTRA_SERVICES CHECK_SELINUX ALERT_EMAIL COOLDOWN_MIN
#            STATE_DIR METRICS_CSV LOG_FILE LOCK_FILE EXCLUDE_FSTYPES
# Cron     : */5 * * * * root /opt/cybershield/monitor.sh -q  (/etc/cron.d)
# Needs    : bash 4.4+, procps-ng, gawk, coreutils, util-linux (flock),
#            systemd (systemctl); s-nail/mailx only for e-mail alerts
# Exit     : 0 all readings normal | 2 bad option or setting | 3 missing
#            prerequisite | 4 not root | 5 at least one alert | 6 already running
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
CONFIG_KEYS=(CPU_LIMIT MEM_LIMIT DISK_LIMIT LOAD_FACTOR SAMPLE_SECONDS SERVICES
             EXTRA_SERVICES CHECK_SELINUX ALERT_EMAIL COOLDOWN_MIN STATE_DIR
             METRICS_CSV LOG_FILE LOCK_FILE EXCLUDE_FSTYPES OS_RELEASE)
ALERTS=0
DISK_MAX=0
DISK_MAX_MOUNT="/"

apply_defaults() {
    CPU_LIMIT="${CPU_LIMIT:-85}"
    MEM_LIMIT="${MEM_LIMIT:-90}"
    DISK_LIMIT="${DISK_LIMIT:-80}"
    LOAD_FACTOR="${LOAD_FACTOR:-1}"
    SAMPLE_SECONDS="${SAMPLE_SECONDS:-1}"
    SERVICES="${SERVICES:-}"
    EXTRA_SERVICES="${EXTRA_SERVICES:-}"
    CHECK_SELINUX="${CHECK_SELINUX:-yes}"
    ALERT_EMAIL="${ALERT_EMAIL:-}"
    COOLDOWN_MIN="${COOLDOWN_MIN:-60}"
    STATE_DIR="${STATE_DIR:-/var/tmp/cybershield}"
    METRICS_CSV="${METRICS_CSV:-/var/log/cybershield/metrics.csv}"
    LOG_FILE="${LOG_FILE:-/var/log/cybershield/monitor.log}"
    LOCK_FILE="${LOCK_FILE:-/run/lock/cybershield-monitor.lock}"
    EXCLUDE_FSTYPES="${EXCLUDE_FSTYPES:-tmpfs devtmpfs squashfs efivarfs iso9660 vboxsf}"
    OS_RELEASE="${OS_RELEASE:-/etc/os-release}"
}

parse_args() {
    while (( $# )); do
        case $1 in
            -q|--quiet)   QUIET=1; shift ;;
            -c|--config)  shift 2 ;;
            -h|--help)    usage; exit 0 ;;
            -V|--version) echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
            *)            echo "Unknown option: $1" >&2; usage >&2; exit "$EX_USAGE" ;;
        esac
    done
}

# ----- Alerting --------------------------------------------------------------

# Send an e-mail for alert KEY, but not more often than every COOLDOWN_MIN
notify_email() {
    local key=$1 text=$2 stamp
    if [[ -z $ALERT_EMAIL ]]; then return 0; fi
    if ! command -v mail >/dev/null 2>&1; then
        log WARN "'mail' is not installed, cannot e-mail the alert"
        return 0
    fi
    mkdir -p -- "$STATE_DIR" 2>/dev/null || true
    stamp="$STATE_DIR/mail_${key}"
    if [[ -n $(find "$stamp" -mmin -"$COOLDOWN_MIN" 2>/dev/null) ]]; then
        return 0                                # already e-mailed recently
    fi
    if printf '%s on %s\n' "$text" "$(hostname -s)" | mail -s "[CyberShield] ALERT: $key" "$ALERT_EMAIL"; then
        touch -- "$stamp" 2>/dev/null || true
    else
        log WARN "Could not e-mail the alert to $ALERT_EMAIL"
    fi
}

# send_alert KEY TEXT : count the alert, log it (journal) and e-mail it
send_alert() {
    ALERTS=$((ALERTS + 1))
    log ALERT "$2"
    notify_email "$1" "$2"
}

# ----- Checks ----------------------------------------------------------------

# CPU % busy between two samples of /proc/stat (idle + iowait count as idle)
get_cpu_usage() {
    local _ u1 n1 s1 i1 w1 q1 sq1 st1 u2 n2 s2 i2 w2 q2 sq2 st2 total idle
    read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ </proc/stat
    sleep "$SAMPLE_SECONDS"
    read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ </proc/stat
    total=$(( (u2 + n2 + s2 + i2 + w2 + q2 + sq2 + st2) - (u1 + n1 + s1 + i1 + w1 + q1 + sq1 + st1) ))
    idle=$(( (i2 + w2) - (i1 + w1) ))
    if (( total <= 0 )); then echo 0; else echo $(( (total - idle) * 100 / total )); fi
}

check_cpu() {
    local used
    used=$(get_cpu_usage)
    CPU_USED=$used
    log INFO "CPU used: ${used}%"
    if (( used >= CPU_LIMIT )); then
        send_alert cpu "CPU usage is ${used}% (limit ${CPU_LIMIT}%)"
    fi
}

# Memory in use from /proc/meminfo (MemAvailable; same on every language)
check_memory() {
    local used
    used=$(awk '/^MemTotal:/ {t = $2} /^MemAvailable:/ {a = $2}
                END {if (t > 0) printf "%d", (t - a) * 100 / t}' /proc/meminfo)
    if [[ ! $used =~ ^[0-9]+$ ]]; then
        send_alert mem "Cannot read memory usage from /proc/meminfo"
        return 0
    fi
    MEM_USED=$used
    log INFO "Memory used: ${used}%"
    if (( used >= MEM_LIMIT )); then
        send_alert mem "Memory usage is ${used}% (limit ${MEM_LIMIT}%)"
    fi
}

# Every mounted file system (RH134 ch.5 storage), mount points with spaces ok
check_disk() {
    local used mount t
    local -a excl=()
    for t in $EXCLUDE_FSTYPES; do excl+=(-x "$t"); done
    while read -r used mount; do
        log INFO "Disk $mount used: ${used}%"
        if (( used > DISK_MAX )); then DISK_MAX=$used; DISK_MAX_MOUNT=$mount; fi
        if (( used >= DISK_LIMIT )); then
            send_alert "disk_${mount//[^A-Za-z0-9]/_}" "Disk $mount is ${used}% full (limit ${DISK_LIMIT}%)"
        fi
    done < <(df -P "${excl[@]}" 2>/dev/null |
             awk 'NR > 1 {u = $5; sub(/%/, "", u); m = $6
                          for (i = 7; i <= NF; i++) m = m " " $i
                          print u, m}')
}

# 1-minute load average against cores x LOAD_FACTOR
check_load() {
    local load cores
    load=$(cut -d' ' -f1 /proc/loadavg)
    cores=$(nproc)
    LOAD1=$load
    log INFO "Load average: $load (CPU cores: $cores, factor: $LOAD_FACTOR)"
    if awk -v l="$load" -v c="$cores" -v f="$LOAD_FACTOR" 'BEGIN {exit !(l > c * f)}'; then
        send_alert load "Load average $load is higher than $cores cores x $LOAD_FACTOR"
    fi
}

# RHEL must run SELinux in Enforcing mode (RH134 ch.4: getenforce)
check_selinux() {
    local mode
    if [[ $CHECK_SELINUX != yes ]]; then return 0; fi
    if ! command -v getenforce >/dev/null 2>&1; then return 0; fi
    mode=$(getenforce 2>/dev/null || echo Unknown)
    if [[ $mode == Enforcing ]]; then
        log INFO "SELinux mode: Enforcing"
    else
        send_alert selinux "SELinux mode is $mode (expected Enforcing)"
    fi
}

# Default service names for this OS (RHEL family or Debian family)
default_services() {
    local ids
    # read ID and ID_LIKE as text (the file is not executed)
    ids=" $(grep -E '^(ID|ID_LIKE)=' "$OS_RELEASE" 2>/dev/null | cut -d= -f2 | tr -d '"' | tr '\n' ' ' || true) "
    case $ids in
        *" rhel "* | *" fedora "* | *" centos "*) echo "sshd firewalld chronyd crond rsyslog auditd" ;;
        *" debian "* | *" ubuntu "*)               echo "ssh ufw chrony cron rsyslog auditd" ;;
        *)                                         echo "sshd" ;;
    esac
}

# Key services must be active; a service that is not installed is skipped
check_services() {
    local svc state list
    list="${SERVICES:-$(default_services)} $EXTRA_SERVICES"
    if ! command -v systemctl >/dev/null 2>&1; then
        log WARN "systemctl not found, service checks skipped"
        return 0
    fi
    for svc in $list; do
        state=$(systemctl show -p LoadState --value "$svc" 2>/dev/null || true)
        if [[ $state == not-found ]]; then
            log WARN "Service $svc is not installed on this host, skipped"
        elif systemctl is-active --quiet "$svc"; then
            log INFO "Service $svc: running"
        else
            send_alert "svc_$svc" "Service $svc is not running"
        fi
    done
}

# Append one line per run to the CSV file (header written once)
write_metrics() {
    mkdir -p -- "$(dirname -- "$METRICS_CSV")" 2>/dev/null || true
    if [[ ! -s $METRICS_CSV ]]; then
        echo "timestamp,cpu_pct,mem_pct,disk_max_pct,disk_max_mount,load1,alerts" >"$METRICS_CSV" 2>/dev/null || true
    fi
    printf '%s,%s,%s,%s,"%s",%s,%s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$CPU_USED" "$MEM_USED" \
        "$DISK_MAX" "$DISK_MAX_MOUNT" "$LOAD1" "$ALERTS" >>"$METRICS_CSV" 2>/dev/null \
        || log WARN "Cannot write $METRICS_CSV"
}

# ----- Main ------------------------------------------------------------------
main() {
    CPU_USED=0; MEM_USED=0; LOAD1=0
    find_config_arg "$@"
    load_config "$CONF_FILE" "${CONFIG_KEYS[@]}"
    apply_defaults
    parse_args "$@"
    require_root
    init_logging
    require_cmd awk df nproc sleep flock find
    [[ -r /proc/stat && -r /proc/meminfo && -r /proc/loadavg ]] \
        || die "$EX_PREREQ" "/proc is not available"
    validate_int CPU_LIMIT "$CPU_LIMIT" 1 100
    validate_int MEM_LIMIT "$MEM_LIMIT" 1 100
    validate_int DISK_LIMIT "$DISK_LIMIT" 1 100
    validate_int LOAD_FACTOR "$LOAD_FACTOR" 1 1000
    validate_int SAMPLE_SECONDS "$SAMPLE_SECONDS" 1 60
    validate_int COOLDOWN_MIN "$COOLDOWN_MIN" 1 100000
    acquire_lock

    check_cpu
    check_memory
    check_disk
    check_load
    check_selinux
    check_services
    write_metrics

    if (( ALERTS > 0 )); then
        log WARN "$ALERTS alert(s) raised"
        exit "$EX_ALERT"
    fi
    log INFO "All checks passed"
}

main "$@"
