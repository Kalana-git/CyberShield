#!/usr/bin/bash
#==============================================================================
# user_mgmt.sh - User management and audit for CyberShield servers
#------------------------------------------------------------------------------
# Version  : 2.0.0     Author: Kalana Supasan - COMP2000 Assignment 2026
# Purpose  : Add, remove, lock and unlock users, set folder permissions, list
#            users and audit accounts and permissions against least privilege.
#            Every action is written to the log file.
# Usage    : sudo user_mgmt.sh [options] ACTION [ARGUMENTS]
#              add    <user> <role>   create user; roles: admin | analyst | staff
#              remove <user>          archive the home folder, then delete user
#              lock   <user>          disable the account
#              unlock <user>          enable the account again
#              perms  <user> <dir>    give <user> the folder (dirs 750, files 640)
#              list                   show normal users (no root needed)
#              audit                  report risky accounts and permissions
#            Options: -y, --yes (no confirmation)   -n, --dry-run (change nothing)
#                     -c, --config FILE   -h, --help   -V, --version
# Roles    : admin = wheel (RHEL) or sudo group, analyst = cs_analysts,
#            staff = cs_staff
# Safety   : only normal accounts (UID 1000 and up) can be changed, you cannot
#            lock or remove yourself, and permissions can only be changed
#            below the folders in ALLOWED_BASES.
# Settings : KEY=value lines in the config file or environment variables:
#            ARCHIVE_DIR MIN_UID ALLOWED_BASES CRITICAL_DIR ANALYST_GROUP
#            STAFF_GROUP ADMIN_GROUP PASSWORD_MAX_DAYS LOG_FILE
# Needs    : bash 4.4+, shadow-utils (useradd, usermod, chage, chpasswd),
#            coreutils, tar, findutils, gawk; policycoreutils (restorecon)
# Exit     : 0 success | 1 error | 2 bad usage or input | 3 missing
#            prerequisite | 4 not root | 5 audit found problems
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
CONFIG_KEYS=(ARCHIVE_DIR MIN_UID ALLOWED_BASES CRITICAL_DIR ANALYST_GROUP
             STAFF_GROUP ADMIN_GROUP PASSWORD_MAX_DAYS LOG_FILE)
readonly USER_REGEX='^[a-z][a-z0-9_-]{2,31}$'      # 3-32 characters
ASSUME_YES=0
DRY_RUN=0
FINDINGS=0
USER_NAME=""

apply_defaults() {
    ARCHIVE_DIR="${ARCHIVE_DIR:-/backup/removed_users}"
    MIN_UID="${MIN_UID:-1000}"
    ALLOWED_BASES="${ALLOWED_BASES:-/var/data /srv /opt/cybershield /home}"
    CRITICAL_DIR="${CRITICAL_DIR:-/var/data/threat_logs}"
    ANALYST_GROUP="${ANALYST_GROUP:-cs_analysts}"
    STAFF_GROUP="${STAFF_GROUP:-cs_staff}"
    ADMIN_GROUP="${ADMIN_GROUP:-}"
    PASSWORD_MAX_DAYS="${PASSWORD_MAX_DAYS:-90}"
    LOG_FILE="${LOG_FILE:-/var/log/cybershield/user_mgmt.log}"
}

# ----- Checks ----------------------------------------------------------------

# The username must match the pattern (this also blocks ; & $ spaces and /)
check_name() {
    if [[ ! $USER_NAME =~ $USER_REGEX ]]; then
        die "$EX_USAGE" "Invalid username '$USER_NAME' (3-32 characters: a-z, 0-9, - and _, starting with a letter)"
    fi
}

# The account must exist, be a normal user, and not be the person using sudo
check_normal_user() {
    local uid
    if ! id "$USER_NAME" >/dev/null 2>&1; then die "$EX_FAIL" "User $USER_NAME does not exist"; fi
    uid=$(id -u "$USER_NAME")
    if (( uid < MIN_UID )); then
        die "$EX_USAGE" "Refusing to change system account $USER_NAME (UID $uid)"
    fi
    if [[ $USER_NAME == "${SUDO_USER:-}" ]]; then
        die "$EX_USAGE" "Refusing to change your own account ($USER_NAME)"
    fi
}

# Role name -> Linux group (empty output = unknown role)
role_to_group() {
    case $1 in
        admin) admin_group ;;
        analyst) echo "$ANALYST_GROUP" ;;
        staff)   echo "$STAFF_GROUP" ;;
        *)       echo "" ;;
    esac
}

# Administrator group: wheel on RHEL (RH124/RH134), sudo on Debian/Ubuntu
admin_group() {
    if [[ -n $ADMIN_GROUP ]]; then echo "$ADMIN_GROUP"
    elif getent group wheel >/dev/null; then echo "wheel"
    else echo "sudo"
    fi
}

# Remove a half-created account again and stop
rollback() {
    userdel -r "$USER_NAME" >/dev/null 2>&1 || true
    die "$EX_FAIL" "$1 - the new account was removed again"
}

# ----- User actions ----------------------------------------------------------

add_user() {
    local role=$1 group password
    group=$(role_to_group "$role")
    if [[ -z $group ]]; then die "$EX_USAGE" "Unknown role '$role' (use admin, analyst or staff)"; fi
    if id "$USER_NAME" >/dev/null 2>&1; then die "$EX_FAIL" "User $USER_NAME already exists"; fi
    if (( DRY_RUN )); then
        log INFO "DRY-RUN: would create user $USER_NAME (role $role, group $group, home mode 700, password change forced, expiry ${PASSWORD_MAX_DAYS} days)"
        return 0
    fi
    if ! getent group "$group" >/dev/null; then
        groupadd "$group" || die "$EX_FAIL" "Cannot create group $group"
    fi
    useradd -m -G "$group" "$USER_NAME" || die "$EX_FAIL" "useradd failed"

    password=$(head -c 12 /dev/urandom | base64)          # 16 random characters
    if [[ -z $password ]]; then rollback "Could not generate a password"; fi
    if ! printf '%s:%s\n' "$USER_NAME" "$password" | chpasswd 2>/dev/null; then
        rollback "Could not set the password"
    fi
    chage -d 0 "$USER_NAME" || rollback "chage failed"                         # change at first login
    chage -M "$PASSWORD_MAX_DAYS" -W 7 "$USER_NAME" || rollback "chage failed" # expiry + warning
    chmod 700 -- "/home/$USER_NAME" || rollback "chmod failed"                 # only the user

    log INFO "Created user $USER_NAME (role $role, group $group)"
    echo "Temporary password: $password   (must be changed at first login)"
}

remove_user() {
    local answer="" home archive
    check_normal_user
    home=$(getent passwd "$USER_NAME" | cut -d: -f6)
    archive="$ARCHIVE_DIR/${USER_NAME}_$(date +%Y%m%d_%H%M%S).tar.gz"
    if (( DRY_RUN )); then
        log INFO "DRY-RUN: would archive $home to $archive and delete user $USER_NAME"
        return 0
    fi
    if (( ! ASSUME_YES )); then
        read -r -p "Delete $USER_NAME and archive the home folder? (y/n) " answer || true
        if [[ $answer != y ]]; then
            log INFO "Removal of $USER_NAME cancelled"
            exit 0
        fi
    fi
    if [[ ! -d $ARCHIVE_DIR ]]; then
        mkdir -p -- "$ARCHIVE_DIR" || die "$EX_PREREQ" "Cannot create $ARCHIVE_DIR"
        fix_selinux_context "$ARCHIVE_DIR"
    fi
    chmod 700 -- "$ARCHIVE_DIR"
    if [[ -d $home ]]; then
        # the archive may hold keys and secrets: private file, checked before deleting
        if ! ( umask 077; tar -czf "$archive" -C "$(dirname -- "$home")" -- "$(basename -- "$home")" ) \
            || ! tar -tzf "$archive" >/dev/null 2>&1; then
            rm -f -- "$archive"
            die "$EX_FAIL" "Could not archive $home - user $USER_NAME was NOT removed"
        fi
    fi
    if ! userdel -r "$USER_NAME" 2>/dev/null; then
        die "$EX_FAIL" "userdel failed (is $USER_NAME logged in?). Archive kept: $archive"
    fi
    log INFO "Removed user $USER_NAME (home archived in $archive)"
}

lock_user() {
    check_normal_user
    if (( DRY_RUN )); then log INFO "DRY-RUN: would lock user $USER_NAME"; return 0; fi
    usermod -L "$USER_NAME" || die "$EX_FAIL" "usermod failed"
    chage -E 0 "$USER_NAME" || die "$EX_FAIL" "chage failed"
    log INFO "Locked user $USER_NAME"
}

unlock_user() {
    check_normal_user
    if (( DRY_RUN )); then log INFO "DRY-RUN: would unlock user $USER_NAME"; return 0; fi
    usermod -U "$USER_NAME" || die "$EX_FAIL" "usermod failed"
    chage -E -1 "$USER_NAME" || die "$EX_FAIL" "chage failed"
    log INFO "Unlocked user $USER_NAME"
}

# Owner = full access, group = read, others = nothing
# (folders rwxr-x---, files rw-r-----). Only below ALLOWED_BASES.
set_perms() {
    local dir=$1 real base allowed=0
    check_normal_user
    if [[ -z $dir ]]; then die "$EX_USAGE" "Missing <directory> (usage: perms <user> <directory>)"; fi
    if [[ ! -d $dir ]]; then die "$EX_FAIL" "Directory $dir does not exist"; fi
    real=$(realpath -e -- "$dir") || die "$EX_FAIL" "Cannot resolve $dir"
    for base in $ALLOWED_BASES; do
        case $real in "$base"/*) allowed=1 ;; esac
    done
    if (( ! allowed )); then
        die "$EX_USAGE" "Refusing to change $real (allowed only below: $ALLOWED_BASES)"
    fi
    if (( DRY_RUN )); then
        log INFO "DRY-RUN: would give $USER_NAME ownership of $real (dirs 750, files 640)"
        return 0
    fi
    chown -hR "$USER_NAME":"$(id -gn "$USER_NAME")" -- "$real" || die "$EX_FAIL" "chown failed"
    chmod -R u=rwX,g=rX,o= -- "$real" || die "$EX_FAIL" "chmod failed"
    fix_selinux_context "$real"
    log INFO "Set owner $USER_NAME and mode 750/640 on $real"
}

# Normal accounts with their state and groups (passwd -S: L/LK locked, P/PS ok)
list_users() {
    local name uid state
    echo "Normal users (UID $MIN_UID and above):"
    printf '%-18s %-6s %-8s %s\n' "USER" "UID" "STATE" "GROUPS"
    while IFS=: read -r name _ uid _; do
        if (( uid >= MIN_UID && uid < 60000 )); then
            if (( EUID == 0 )); then
                state=$(passwd -S "$name" 2>/dev/null | awk '{print $2}' || true)
            else
                state=$(sudo -n passwd -S "$name" 2>/dev/null | awk '{print $2}' || true)
            fi
            case ${state:-?} in
                L|LK) state="locked" ;;
                P|PS) state="active" ;;
                NP)   state="no-pass" ;;
                *)    state="?" ;;
            esac
            printf '%-18s %-6s %-8s %s\n' "$name" "$uid" "$state" "$(id -Gn "$name" | tr ' ' ',')"
        fi
    done < <(getent passwd)
}

# ----- Audit -----------------------------------------------------------------

finding() {
    FINDINGS=$((FINDINGS + 1))
    log WARN "FINDING: $*"
}

# Report accounts and permissions that break least privilege; exit 5 on findings
audit() {
    local admin members name pw uid mode wf
    admin=$(admin_group)
    echo "=== 1. Normal accounts ==="
    list_users
    echo "=== 2. Members of the administrator group ($admin) ==="
    members=$(getent group "$admin" | cut -d: -f4 || true)
    echo "  ${members:-(none)}"

    echo "=== 3. Extra UID 0 accounts ==="
    while IFS=: read -r name _ uid _; do
        if [[ $uid == 0 && $name != root ]]; then finding "Account '$name' has UID 0 (root rights)"; fi
    done < <(getent passwd)

    echo "=== 4. Accounts without a password ==="
    while IFS=: read -r name pw _; do
        if [[ -z $pw ]]; then finding "Account '$name' has an EMPTY password"; fi
    done </etc/shadow

    echo "=== 5. Critical directory: $CRITICAL_DIR ==="
    if [[ ! -d $CRITICAL_DIR ]]; then
        log WARN "Critical directory $CRITICAL_DIR does not exist on this host, skipped"
    else
        mode=$(stat -c %a -- "$CRITICAL_DIR")
        echo "  mode=$mode owner=$(stat -c %U:%G -- "$CRITICAL_DIR")"
        # bit test on the octal mode: any permission for "others" is too open
        if (( 8#$mode & 8#007 )); then
            finding "$CRITICAL_DIR is accessible to others (mode $mode, expected 750 or stricter)"
        fi
        while IFS= read -r wf; do
            finding "World-writable item: $wf"
        done < <(find "$CRITICAL_DIR" ! -type l -perm -0002 -print 2>/dev/null)
    fi

    if (( FINDINGS > 0 )); then
        log WARN "Audit finished: $FINDINGS finding(s)"
        exit "$EX_ALERT"
    fi
    log INFO "Audit finished: no findings"
}

# ----- Main ------------------------------------------------------------------
main() {
    local arg action third
    local -a args=()
    find_config_arg "$@"
    load_config "$CONF_FILE" "${CONFIG_KEYS[@]}"
    apply_defaults
    while (( $# )); do
        arg=$1; shift
        case $arg in
            -y|--yes)     ASSUME_YES=1 ;;
            -n|--dry-run) DRY_RUN=1 ;;
            -c|--config)  shift || true ;;
            -h|--help)    usage; exit 0 ;;
            -V|--version) echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
            -*)           echo "Unknown option: $arg" >&2; usage >&2; exit "$EX_USAGE" ;;
            *)            args+=("$arg") ;;
        esac
    done
    action="${args[0]:-}"
    USER_NAME="${args[1]:-}"
    third="${args[2]:-}"

    validate_int MIN_UID "$MIN_UID" 1 60000
    validate_int PASSWORD_MAX_DAYS "$PASSWORD_MAX_DAYS" 1 99999
    case $action in
        list)  list_users; exit 0 ;;
        add|remove|lock|unlock|perms|audit) ;;
        *)     usage >&2; exit "$EX_USAGE" ;;
    esac

    require_root
    init_logging
    require_cmd useradd userdel usermod chage getent find stat tar realpath

    case $action in
        add)    check_name
                if [[ -z $third ]]; then usage >&2; exit "$EX_USAGE"; fi
                add_user "$third" ;;
        remove) check_name; remove_user ;;
        lock)   check_name; lock_user ;;
        unlock) check_name; unlock_user ;;
        perms)  check_name; set_perms "$third" ;;
        audit)  audit ;;
    esac
}

main "$@"
