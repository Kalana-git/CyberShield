#!/usr/bin/bash
#==============================================================================
# backup.sh - Automated encrypted backup for CyberShield Solutions
#------------------------------------------------------------------------------
# Version  : 2.0.0     Author: Kalana Supasan - COMP2000 Assignment 2026
# Run on   : BKP-01 (192.168.2.30), as root
# Purpose  : Pull a dump of the PostgreSQL database (DB-01) and the threat
#            analysis logs (TAS-01) over SSH, compress and encrypt them (GPG,
#            AES-256), verify every file, write a SHA-256 checksum and delete
#            backups older than the retention period.
# Usage    : backup.sh [options]
#              -n, --dry-run      run all checks, create and delete nothing
#                  --verify FILE  check checksum and decryption of a backup
#              -c, --config FILE  settings file (default
#                                 /etc/cybershield/cybershield.conf)
#              -h, --help         show this help
#              -V, --version      show the version
# Settings : KEY=value lines in the config file or environment variables:
#            DB_HOST TAS_HOST SSH_USER DB_NAME TAS_LOG_PARENT TAS_LOG_NAME
#            BACKUP_DIR KEEP_DAYS MIN_FREE_MB ENCRYPT GPG_PASS_FILE LOG_FILE
#            LOCK_FILE   (DB_NAME empty = skip the database dump)
# Cron     : 0 2 * * * root /opt/cybershield/backup.sh   (/etc/cron.d file)
# Needs    : bash 4.4+, openssh-clients, gnupg2, gzip, tar, findutils,
#            util-linux (flock), coreutils; policycoreutils (restorecon)
# Exit     : 0 success | 1 error | 2 bad option or setting | 3 missing
#            prerequisite | 4 not root | 6 another backup is running
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
CONFIG_KEYS=(DB_HOST TAS_HOST SSH_USER DB_NAME TAS_LOG_PARENT TAS_LOG_NAME
             BACKUP_DIR KEEP_DAYS MIN_FREE_MB ENCRYPT GPG_PASS_FILE LOG_FILE LOCK_FILE)
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new)
DRY_RUN=0
VERIFY_FILE=""
DATE=$(date +%Y%m%d_%H%M%S)

# Defaults are applied after the config file, so file/env values win
apply_defaults() {
    DB_HOST="${DB_HOST:-192.168.2.10}"
    TAS_HOST="${TAS_HOST:-192.168.2.20}"
    SSH_USER="${SSH_USER:-backup}"
    DB_NAME="${DB_NAME-cybershield}"
    TAS_LOG_PARENT="${TAS_LOG_PARENT:-/var/log}"
    TAS_LOG_NAME="${TAS_LOG_NAME:-threat-analysis}"
    BACKUP_DIR="${BACKUP_DIR:-/backup/cybershield}"
    KEEP_DAYS="${KEEP_DAYS:-30}"
    MIN_FREE_MB="${MIN_FREE_MB:-1024}"
    ENCRYPT="${ENCRYPT:-yes}"
    GPG_PASS_FILE="${GPG_PASS_FILE:-/etc/cybershield/backup.pass}"
    LOG_FILE="${LOG_FILE:-/var/log/cybershield/backup.log}"
    LOCK_FILE="${LOCK_FILE:-/run/lock/cybershield-backup.lock}"
}

parse_args() {
    while (( $# )); do
        case $1 in
            -n|--dry-run)  DRY_RUN=1; shift ;;
            --verify)      VERIFY_FILE=${2:?--verify needs a file name}; shift 2 ;;
            -c|--config)   shift 2 ;;
            -h|--help)     usage; exit 0 ;;
            -V|--version)  echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
            *)             echo "Unknown option: $1" >&2; usage >&2; exit "$EX_USAGE" ;;
        esac
    done
}

# Validate every setting before it is used (several go into remote commands)
validate_settings() {
    local h
    validate_int KEEP_DAYS "$KEEP_DAYS" 1 3650
    validate_int MIN_FREE_MB "$MIN_FREE_MB" 0 1000000000
    for h in "$DB_HOST" "$TAS_HOST"; do
        [[ $h =~ ^[A-Za-z0-9._-]+$ ]] || die "$EX_USAGE" "Invalid host name '$h'"
    done
    [[ $SSH_USER =~ ^[a-z_][a-z0-9_-]*$ ]] || die "$EX_USAGE" "Invalid SSH_USER '$SSH_USER'"
    if [[ -n $DB_NAME && ! $DB_NAME =~ ^[A-Za-z0-9_]+$ ]]; then
        die "$EX_USAGE" "Invalid DB_NAME '$DB_NAME'"
    fi
    [[ $TAS_LOG_NAME =~ ^[A-Za-z0-9_.-]+$ ]] || die "$EX_USAGE" "Invalid TAS_LOG_NAME '$TAS_LOG_NAME'"
    [[ $TAS_LOG_PARENT =~ ^/[A-Za-z0-9_./-]*$ ]] || die "$EX_USAGE" "Invalid TAS_LOG_PARENT '$TAS_LOG_PARENT'"
    if [[ $BACKUP_DIR != /* || $BACKUP_DIR == / ]]; then
        die "$EX_USAGE" "BACKUP_DIR must be an absolute path other than / (got '$BACKUP_DIR')"
    fi
    if [[ $ENCRYPT != yes && $ENCRYPT != no ]]; then
        die "$EX_USAGE" "ENCRYPT must be yes or no (got '$ENCRYPT')"
    fi
}

# The passphrase file must exist and be private (mode 600 or 400)
check_crypto() {
    local mode
    require_cmd gpg
    [[ -r $GPG_PASS_FILE ]] || die "$EX_PREREQ" "Passphrase file not readable: $GPG_PASS_FILE"
    mode=$(stat -c %a -- "$GPG_PASS_FILE")
    if (( 8#$mode & 8#077 )); then
        die "$EX_PREREQ" "Passphrase file $GPG_PASS_FILE must be private (chmod 600)"
    fi
}

# Create the backup folder (mode 700, SELinux label restored)
prepare_backup_dir() {
    if [[ -d $BACKUP_DIR ]]; then
        if (( ! DRY_RUN )); then chmod 700 -- "$BACKUP_DIR"; fi
        return 0
    fi
    if (( DRY_RUN )); then
        log INFO "DRY-RUN: would create $BACKUP_DIR"
        return 0
    fi
    mkdir -p -- "$BACKUP_DIR" || die "$EX_PREREQ" "Cannot create $BACKUP_DIR"
    chmod 700 -- "$BACKUP_DIR"
    fix_selinux_context "$BACKUP_DIR"
    log INFO "Created backup directory $BACKUP_DIR"
}

# Refuse to start when the backup disk is nearly full
check_free_space() {
    local avail
    if [[ ! -d $BACKUP_DIR ]]; then return 0; fi
    avail=$(df -Pm -- "$BACKUP_DIR" | awk 'NR==2 {print $4}')
    log INFO "Free space in $BACKUP_DIR: ${avail} MB (minimum ${MIN_FREE_MB} MB)"
    if (( avail < MIN_FREE_MB )); then
        die "$EX_FAIL" "Only ${avail} MB free in $BACKUP_DIR (need ${MIN_FREE_MB} MB)"
    fi
}

# Both servers must answer over SSH with key login (no password prompt)
check_ssh() {
    local host
    local -a hosts=()
    if [[ -n $DB_NAME ]]; then hosts+=("$DB_HOST"); fi
    hosts+=("$TAS_HOST")
    for host in "${hosts[@]}"; do
        if ! ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" true; then
            die "$EX_FAIL" "Cannot connect to $host over SSH"
        fi
    done
}

# Read data on stdin and store it in file $1 (GPG encrypted when ENCRYPT=yes)
store_stream() {
    if [[ $ENCRYPT == yes ]]; then
        gpg --batch --yes --quiet --pinentry-mode loopback \
            --passphrase-file "$GPG_PASS_FILE" --symmetric \
            --cipher-algo AES256 --output "$1"
    else
        cat > "$1"
    fi
}

# verify_file FILE yes|no : the file must hold real data (decrypts if needed,
# decompresses without errors and has at least one byte of content)
verify_file() {
    local f=$1 encrypted=$2 size
    [[ -s $f ]] || return 1
    if [[ $encrypted == yes ]]; then
        size=$(gpg --batch --quiet --pinentry-mode loopback \
                   --passphrase-file "$GPG_PASS_FILE" --decrypt "$f" 2>/dev/null |
               gzip -dc 2>/dev/null | wc -c) || return 1
    else
        size=$(gzip -dc "$f" 2>/dev/null | wc -c) || return 1
    fi
    (( size > 0 ))
}

# verify_archive FILE : stand-alone check of an existing backup (--verify)
verify_archive() {
    local f=$1 enc=no
    [[ -f $f ]] || die "$EX_PREREQ" "Backup file not found: $f"
    [[ -f $f.sha256 ]] || die "$EX_PREREQ" "Checksum file missing: $f.sha256"
    if ! ( cd -- "$(dirname -- "$f")" && sha256sum --check --quiet -- "$(basename -- "$f").sha256" ) >/dev/null 2>&1; then
        die "$EX_FAIL" "Checksum mismatch for $f"
    fi
    log INFO "Checksum OK: ${f##*/}"
    if [[ $f == *.gpg ]]; then enc=yes; check_crypto; fi
    if ! verify_file "$f" "$enc"; then
        die "$EX_FAIL" "Backup $f cannot be decrypted/decompressed or is empty"
    fi
    log INFO "Content OK: ${f##*/} decrypts and decompresses"
}

# Verify the unfinished file, give it its final name and write its checksum
finish_file() {
    local partial=$1 final=$2
    if ! verify_file "$partial" "$ENCRYPT"; then
        die "$EX_FAIL" "Backup file is empty or corrupt: ${final##*/}"
    fi
    mv -f -- "$partial" "$final"
    chmod 600 -- "$final"
    ( cd -- "$BACKUP_DIR" && sha256sum -- "${final##*/}" > "${final##*/}.sha256" )
    log INFO "Backup OK: $final ($(du -h -- "$final" | cut -f1))"
}

# Dump the database from DB-01 (skipped when DB_NAME is empty)
backup_database() {
    local file ext=sql.gz
    local -a st=()
    if [[ -z $DB_NAME ]]; then
        log INFO "DB_NAME is empty: database backup skipped"
        return 0
    fi
    if [[ $ENCRYPT == yes ]]; then ext=sql.gz.gpg; fi
    file="$BACKUP_DIR/db_${DB_NAME}_$DATE.$ext"
    log INFO "Backing up database $DB_NAME from $DB_HOST"
    if (( DRY_RUN )); then
        log INFO "DRY-RUN: would create $file"
        return 0
    fi
    CLEANUP_FILES+=("$file.partial")
    # shellcheck disable=SC2029  # DB_NAME is validated; client-side expansion is intended
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$DB_HOST" "pg_dump $DB_NAME" | gzip | store_stream "$file.partial" \
        || st=("${PIPESTATUS[@]}")
    if (( ${#st[@]} )); then
        die "$EX_FAIL" "Database backup failed (ssh/pg_dump=${st[0]} gzip=${st[1]} store=${st[2]})"
    fi
    finish_file "$file.partial" "$file"
}

# Archive the log folder from the threat analysis server
backup_logs() {
    local file ext=tar.gz
    local -a st=()
    if [[ $ENCRYPT == yes ]]; then ext=tar.gz.gpg; fi
    file="$BACKUP_DIR/tas_logs_$DATE.$ext"
    log INFO "Backing up logs from $TAS_HOST"
    if (( DRY_RUN )); then
        log INFO "DRY-RUN: would create $file"
        return 0
    fi
    CLEANUP_FILES+=("$file.partial")
    # shellcheck disable=SC2029  # paths are validated; client-side expansion is intended
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$TAS_HOST" "tar -czf - -C $TAS_LOG_PARENT $TAS_LOG_NAME" | store_stream "$file.partial" \
        || st=("${PIPESTATUS[@]}")
    if (( ${#st[@]} )); then
        die "$EX_FAIL" "Log backup failed (ssh/tar=${st[0]} store=${st[1]})"
    fi
    finish_file "$file.partial" "$file"
}

# Delete backups (and checksum files) older than KEEP_DAYS, only in BACKUP_DIR
delete_old_backups() {
    local old count=0
    if [[ ! -d $BACKUP_DIR ]]; then return 0; fi
    while IFS= read -r old; do
        if (( DRY_RUN )); then
            log INFO "DRY-RUN: would delete $old"
        else
            rm -f -- "$old"
            log INFO "Deleted old backup: ${old##*/}"
        fi
        count=$((count + 1))
    done < <(find "$BACKUP_DIR" -maxdepth 1 -type f \
                 \( -name 'db_*' -o -name 'tas_logs_*' \) -mtime +"$KEEP_DAYS")
    log INFO "Retention: $count file(s) older than $KEEP_DAYS days"
}

# ----- Main ------------------------------------------------------------------
main() {
    find_config_arg "$@"
    load_config "$CONF_FILE" "${CONFIG_KEYS[@]}"
    apply_defaults
    parse_args "$@"
    require_root
    init_logging
    require_cmd ssh gzip tar find flock df du awk stat sha256sum
    validate_settings

    if [[ -n $VERIFY_FILE ]]; then
        verify_archive "$VERIFY_FILE"
        exit 0
    fi
    if [[ $ENCRYPT == yes ]]; then check_crypto; fi

    prepare_backup_dir
    acquire_lock
    check_free_space
    check_ssh
    log INFO "===== Backup started (encrypt=$ENCRYPT, dry-run=$DRY_RUN) ====="
    backup_database
    backup_logs
    delete_old_backups
    log INFO "===== Backup finished ====="
}

main "$@"
