# CyberShield Solutions – Setup and Execution Guide
**COMP2000 Computer Systems Assignment**  
*A complete, step-by-step, beginner-friendly guide to setting up, configuring, running, and testing the CyberShield automation suite.*

---

## 1. What is CyberShield Solutions?

CyberShield Solutions is a modular enterprise Linux automation suite developed for Red Hat Enterprise Linux 9 (RHEL 9). It consists of four core administrative scripts and an automated test suite:

| Script | Primary Server | Purpose | Key Operations |
|---|---|---|---|
| **`user_mgmt.sh`** | Any Server | User Lifecycle & Access Control | Adds users with predefined roles (`admin`, `analyst`, `staff`), sets folder permissions conforming to least privilege, locks/unlocks accounts, safely archives home directories upon removal, and runs a comprehensive security audit. |
| **`monitor.sh`** | All Servers | Performance & Resource Monitoring | Checks CPU, RAM, Disk partitions, 1-minute load average, SELinux mode (`Enforcing`), and core system services (`sshd`, `firewalld`, `chronyd`, `crond`, etc.). Writes CSV metrics and raises alerts. |
| **`log_analyzer.sh`** | Web / Edge Servers | Intrusion & Error Detection | Scans authentication logs (`/var/log/secure` or `/var/log/auth.log`) for SSH brute-force attempts and scans web logs (`/var/log/nginx/access.log`) for HTTP 4xx/5xx error spikes within configurable time windows. |
| **`backup.sh`** | Backup Server (`BKP-01`) | Disaster Recovery & Archival | Connects securely to the database server (`DB-01`) and threat analysis server (`TAS-01`), pulls data, compresses and encrypts archives using **GPG AES-256**, calculates SHA-256 checksums, and purges archives older than the retention period. |
| **`run_tests.sh`** | Test Environment | Automated Verification | Runs 203 automated test cases covering syntax, strict-mode error traps, boundaries, stubs, and rollbacks. |

---

## 2. Prerequisites & Environment Setup

### 2.1 Supported Environments
The scripts are designed for Linux. You can run them in **A Linux Virtual Machine (Recommended):** Red Hat Enterprise Linux 9, Rocky Linux 9, AlmaLinux 9 running in Oracle VirtualBox or VMware Workstation.

---

### 2.2 Transferring Files & Fixing Line Endings (CRITICAL)

#### Move the files to your Linux VM

**Clone the scripts to the current folder:**
```bash
git clone https://github.com/Kalana-git/CyberShield.git
```

**Move the folder to user's home dir**
```bash
mv CyberShield ~/
```
---

### 2.3 Installing Required Packages

Open a terminal on your Linux machine and install the required utilities:

#### On RHEL 9 / Rocky Linux 9 / AlmaLinux 9:

**Enable EPEL (Extra Packages for Enterprise Linux) for shellcheck:
(On RHEL 9, install the official EPEL RPM):**
```bash
sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm || sudo dnf install -y epel-release || true
```

**Install required system utilities and shellcheck:**
```bash
sudo dnf install -y openssh-clients gnupg2 procps-ng gawk findutils tar gzip \
util-linux policycoreutils shadow-utils s-nail shellcheck
```
*Note: `s-nail` provides the `mail` command for email alerting; `shellcheck` is used by the test suite.*

---

## 3. Installation Step-by-Step

All administrative scripts are designed to live in `/usr/local/sbin`, root-owned with mode `755` (read, write and execute for root; read and execute for group; read and execute for others).

### Step 3.1: Make scripts executable
Navigate to the directory containing the scripts:
```bash
cd ~/CyberShield
chmod +x *.sh
```

### Step 3.2: Create system directories and install the scripts

1. Create configuration directory
```bash
sudo install -d -m 750 /etc/cybershield
```

2. Install scripts into /usr/local/sbin
```bash
sudo install -m 755 -o root -g root backup.sh monitor.sh log_analyzer.sh user_mgmt.sh /usr/local/sbin/
```

3. Create required runtime and log directories
```bash
sudo mkdir -p -m 750 /var/log/cybershield
sudo mkdir -p -m 700 /backup/cybershield
sudo mkdir -p -m 700 /backup/removed_users
sudo mkdir -p -m 750 /var/data/threat_logs
```
4. If using SELinux (RHEL/Rocky), apply default labels
```bash
sudo restorecon -v /usr/local/sbin/*.sh 2>/dev/null || true
sudo restorecon -Rv /var/log/cybershield /backup /var/data 2>/dev/null || true
```
5. Allow non-root users to query account status (needed by "list")
```bash
echo 'ALL ALL=(root) NOPASSWD: /usr/bin/passwd -S *' | sudo tee /etc/sudoers.d/cybershield-list > /dev/null

sudo chmod 440 /etc/sudoers.d/cybershield-list
```

---

## 4. Central Configuration Setup

Settings follow a strict hierarchy:
$$\text{CLI Flags} > \text{Environment Variables} > \text{/etc/cybershield/cybershield.conf} > \text{Built-in Defaults}$$

### Step 4.1: Generate the Backup Encryption Passphrase
The backup script (`backup.sh`) uses symmetric AES-256 encryption. It requires a private passphrase file owned by root with permissions `600` (read/write only by root):

Generate a random 32-byte base64 passphrase:
```bash
head -c 32 /dev/urandom | base64 | sudo tee /etc/cybershield/backup.pass > /dev/null
```

Enforce strict private permissions (exit code 3 if too open!):
```bash
sudo chmod 600 /etc/cybershield/backup.pass
```

### Step 4.2: Create the Central Configuration Files

Create `/etc/cybershield/backup.conf`
```bash
sudo tee /etc/cybershield/backup.conf > /dev/null << 'EOF'
# /etc/cybershield/backup.conf
# backup.sh settings
DB_HOST=192.168.2.10
TAS_HOST=192.168.2.20
SSH_USER=backup
DB_NAME=cybershield
BACKUP_DIR=/backup/cybershield
KEEP_DAYS=30
MIN_FREE_MB=1024
ENCRYPT=yes
GPG_PASS_FILE=/etc/cybershield/backup.pass
EOF
```

Create `/etc/cybershield/monitor.conf`
```bash
sudo tee /etc/cybershield/monitor.conf > /dev/null << 'EOF'
# /etc/cybershield/monitor.conf
# monitor.sh settings
CPU_LIMIT=85
MEM_LIMIT=90
DISK_LIMIT=80
LOAD_FACTOR=1
CHECK_SELINUX=yes
COOLDOWN_MIN=60
EOF
```

Create `/etc/cybershield/log_analyzer.conf`
```bash
sudo tee /etc/cybershield/log_analyzer.conf > /dev/null << 'EOF'
# /etc/cybershield/log_analyzer.conf
# log_analyzer.sh settings
SSH_LIMIT=5
ERROR_LIMIT=100
WINDOW_MIN=60
REPORT_DIR=/var/log/cybershield/reports
REPORT_KEEP_DAYS=30
EOF
```

Create `/etc/cybershield/user_mgmt.conf`
```bash
sudo tee /etc/cybershield/user_mgmt.conf > /dev/null << 'EOF'
# /etc/cybershield/user_mgmt.conf
# user_mgmt.sh settings
ALLOWED_BASES="/var/data /srv /opt/cybershield /home"
CRITICAL_DIR=/var/data/threat_logs
ARCHIVE_DIR=/backup/removed_users
ANALYST_GROUP=cs_analysts
STAFF_GROUP=cs_staff
PASSWORD_MAX_DAYS=90
MIN_UID=1000
EOF
```

### Step 4.3: Secure the Configuration File
The scripts actively verify that the configuration file is root-owned and cannot be edited by others:
```bash
sudo chown root:root /etc/cybershield/backup.conf /etc/cybershield/monitor.conf /etc/cybershield/log_analyzer.conf /etc/cybershield/user_mgmt.conf
```
```bash
sudo chmod 640 /etc/cybershield/cybershield.conf
```

---

## 5. How to Run and Test Each Script

---

### 5.1 User Management & Security Audit (`user_mgmt.sh`)

Manages user creation, permissions, locking, deletion with backup, and auditing.

#### Action 1: Add a User (`add <username> <role>`)
Roles available: `admin`, `analyst`, or `staff`.
- For `admin`: user is added to `wheel` (RHEL) or `sudo` (Ubuntu).
- For `analyst`: user is added to `cs_analysts` (created automatically if missing).
- For `staff`: user is added to `cs_staff` (created automatically if missing).
- Sets home directory to mode `700`.
- Generates a 16-character temporary password and forces a password change upon first login.

```bash
sudo user_mgmt.sh add jayantha analyst
```

If you get an error message while running the above command and it looks like:
```
sudo: user_mgmt.sh: command not found
```

Do the following...

Run:
```bash
sudo visudo
```

Find the line which says:
```
Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin
```

Replace it with:
```
Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin
```

**Sample Output:**
```
2026-10-31 20:31:10 [INFO] user_mgmt.sh: Created user jayantha (role analyst, group cs_analysts)
Temporary password: 4/Lfw6Lf8kkx0ASx   (must be changed at first login)
```

#### Action 2: List Normal Users (`list`)
Does **not** require `sudo`. Lists all non-system users (UID 1000 and up) with their UID, account state (`active`, `locked`, `no-pass`), and group memberships:
```bash
user_mgmt.sh list
```
**Sample Output:**
```
Normal users (UID 1000 and above):
USER               UID    STATE    GROUPS
kaliya             1000   active   kaliya,wheel
jayantha           1001   active   jayantha,cs_analysts
```

#### Action 3: Set Least-Privilege Directory Permissions (`perms <username> <directory>`)
Changes directory ownership to the user, sets directories to `750` (`rwxr-x---`) and files to `640` (`rw-r-----`), and strips all permissions for "others".
*(Must be within `ALLOWED_BASES`)*:

Prepare a directory:
```bash
sudo mkdir -p /var/data/threat_logs
```

```bash
sudo sh -c 'echo "Jayantha said oya innako mn ilaga paara hodata karala pennannan!" > /var/data/threat_logs/analysis_report.txt'
```

Apply permissions:
```bash
sudo user_mgmt.sh perms jayantha /var/data/threat_logs
```

**Sample Output:**
```
2026-10-31 20:38:44 [INFO] user_mgmt.sh: Set owner jayantha and mode 750/640 on /var/data/threat_logs
```

#### Action 4: Lock and Unlock an Account (`lock` / `unlock`)
Disables an account immediately:

Lock the account:
```bash
sudo user_mgmt.sh lock jayantha
```

**Sample Output:**
```
2026-10-31 20:40:13 [INFO] user_mgmt.sh: Locked user jayantha
```

Verify it shows locked:
```bash
user_mgmt.sh list
```

**Sample Output:**
```
Normal users (UID 1000 and above):
USER               UID    STATE    GROUPS
kaliya             1000   active   kaliya,wheel
jayantha           1001   locked   jayantha,cs_analysts
```

Unlock the account:
```bash
sudo user_mgmt.sh unlock jayantha
```

**Sample Output:**
```
2026-10-31 20:48:14 [INFO] user_mgmt.sh: Unlocked user jayantha
```

#### Action 5: Run the Security Audit (`audit`)
Audits:
1. Normal user accounts.
2. Administrative group members.
3. Hidden or unauthorized UID 0 accounts (backdoors).
4. Accounts with empty passwords.
5. Permissive permissions or world-writable files in the critical directory (`CRITICAL_DIR`).
```bash
sudo user_mgmt.sh audit
```
**Sample Output (Healthy system):**
```
=== 1. Normal accounts ===
Normal users (UID 1000 and above):
USER               UID    STATE    GROUPS
kaliya             1000   active   kaliya,wheel
jayantha           1001   active   jayantha,cs_analysts
=== 2. Members of the administrator group (wheel) ===
  kaliya
=== 3. Extra UID 0 accounts ===
=== 4. Accounts without a password ===
=== 5. Critical directory: /var/data/threat_logs ===
  mode=750 owner=jayantha:jayantha
2026-10-31 20:56:57 [INFO] user_mgmt.sh: Audit finished: no findings
```
*(If a vulnerability is found, it logs a warning and exits with code 5).*

#### Action 6: Remove a User with Archive (`remove <username>`)
Before removing the account from the OS, the user's home folder is archived into `/backup/removed_users/username_TIMESTAMP.tar.gz` (mode `600`).
```bash
sudo user_mgmt.sh remove jayantha -y
```
**Sample Output:**
```
2026-10-31 19:41:36 [INFO] user_mgmt.sh: Removed user jayantha (home archived in /backup/removed_users/jayantha_20261031_194136.tar.gz)
```

---

### 5.2 System Performance & Resource Monitor (`monitor.sh`)

Monitors CPU usage, memory usage, disk utilization per mount, system load factor, SELinux enforcement, and systemd service states.

#### Interactive Execution
Run the monitor directly in the terminal:
```bash
sudo monitor.sh
```
**Sample Output:**
```
2026-10-31 20:58:55 [INFO] monitor.sh: CPU used: 26%
2026-10-31 20:58:55 [INFO] monitor.sh: Memory used: 62%
2026-10-31 20:58:55 [INFO] monitor.sh: Disk / used: 17%
2026-10-31 20:58:55 [INFO] monitor.sh: Disk /boot used: 29%
2026-10-31 20:58:55 [INFO] monitor.sh: Load average: 0.19 (CPU cores: 2, factor: 1)
2026-10-31 20:58:55 [INFO] monitor.sh: SELinux mode: Enforcing
2026-10-31 20:58:55 [INFO] monitor.sh: Service sshd: running
2026-10-31 20:58:55 [INFO] monitor.sh: Service firewalld: running
2026-10-31 20:58:55 [INFO] monitor.sh: Service chronyd: running
2026-10-31 20:58:55 [INFO] monitor.sh: Service crond: running
2026-10-31 20:58:55 [INFO] monitor.sh: Service rsyslog: running
2026-10-31 20:58:55 [INFO] monitor.sh: Service auditd: running
2026-10-31 20:58:55 [INFO] monitor.sh: All checks passed
```

#### Inspect Historical CSV Metrics
Every run appends a comma-separated record to `/var/log/cybershield/metrics.csv` for reporting and graphing:
```bash
sudo cat /var/log/cybershield/metrics.csv
```
**Format:**
```
timestamp,cpu_pct,mem_pct,disk_max_pct,disk_max_mount,load1,alerts
2026-10-31T19:42:33,24,61,29,"/boot",0.30,0
2026-10-31T19:47:16,13,60,29,"/boot",0.13,0
2026-10-31T19:48:54,18,60,29,"/boot",0.16,1
2026-10-31T19:49:47,14,60,29,"/boot",0.06,0
2026-10-31T19:50:04,17,60,29,"/boot",0.20,1
2026-10-31T20:00:23,4,61,29,"/boot",0.33,0
2026-10-31T20:58:55,26,62,29,"/boot",0.19,0
```

#### Test Alerting (Breaching a Threshold)
To test how `monitor.sh` handles an alert, override the threshold on the command line:

Set CPU threshold to 1% to trigger an alert
```bash
sudo CPU_LIMIT=1 monitor.sh
```
**Sample Output:**
```
2026-10-31 21:01:56 [INFO] monitor.sh: CPU used: 20%
2026-10-31 21:01:56 [ALERT] monitor.sh: CPU usage is 20% (limit 1%)
2026-10-31 21:01:56 [INFO] monitor.sh: Memory used: 62%
2026-10-31 21:01:56 [INFO] monitor.sh: Disk / used: 17%
2026-10-31 21:01:56 [INFO] monitor.sh: Disk /boot used: 29%
2026-10-31 21:01:56 [INFO] monitor.sh: Load average: 0.15 (CPU cores: 2, factor: 1)
2026-10-31 21:01:56 [INFO] monitor.sh: SELinux mode: Enforcing
2026-10-31 21:01:56 [INFO] monitor.sh: Service sshd: running
2026-10-31 21:01:56 [INFO] monitor.sh: Service firewalld: running
2026-10-31 21:01:56 [INFO] monitor.sh: Service chronyd: running
2026-10-31 21:01:56 [INFO] monitor.sh: Service crond: running
2026-10-31 21:01:56 [INFO] monitor.sh: Service rsyslog: running
2026-10-31 21:01:56 [INFO] monitor.sh: Service auditd: running
2026-10-31 21:01:56 [WARN] monitor.sh: 1 alert(s) raised
```

*(The script exits with code `5` when an alert is raised).*

#### Quiet Mode (Used by Cron)
Suppresses regular output and only prints when an alert or error occurs:
```bash
sudo CPU_LIMIT=1 monitor.sh -q
```
**Sample Output:**
```
2026-10-31 21:03:07 [ALERT] monitor.sh: CPU usage is 11% (limit 1%)
2026-10-31 21:03:07 [WARN] monitor.sh: 1 alert(s) raised
```

### 5.3 Security Log File Analyzer (`log_analyzer.sh`)

Scans system authentication logs (`/var/log/secure` or `/var/log/auth.log`) and Nginx access logs to detect brute-force attacks and error floods.

#### Standard Run (Last 60 Minutes)
```bash
sudo log_analyzer.sh
```
**Sample Output:**
```
===== Log report 2026-10-29 16:15:00 on localhost =====
--- SSH logins from /var/log/secure (last 60 min, 0 = whole log) ---
Total failed passwords: 0   invalid-user attempts: 0
  Source IP                                  Failed  Invalid-user
(no failed logins in this window)
--- Nginx access log: /var/log/nginx/access.log (last 60 min) ---
(Nginx access log not found, skipped)
No alerts raised.
```

#### Custom Time Window & Rotated Logs
Look back over the last 24 hours (1440 minutes), including rotated and gzipped log files (`secure-DATE`, `secure.1`, `secure.2.gz`):
```bash
sudo log_analyzer.sh -w 1440 -r
```

#### Querying systemd Journal Directly
Instead of parsing log files on disk, read directly from systemd:
```bash
sudo log_analyzer.sh --journal
```

#### Simulating an Attack and Triggering an Alert
You can simulate brute-force attacks by injecting mock failed login entries into a test log or system log:

*Inject 6 failed attempts from a simulated attacker IP*
```bash
for i in {1..3}; do
    sudo logger -t sshd -p authpriv.info "Failed password for invalid user admin from 203.0.113.50 port 44212 ssh2"
done
```

*Run the analyzer*
```bash
sudo log_analyzer.sh
```
**Sample Output:**
```
===== Log report 2026-10-29 16:20:00 on localhost =====
--- SSH logins from /var/log/secure (last 60 min) ---
Total failed passwords: 6   invalid-user attempts: 0
  Source IP                                  Failed  Invalid-user
  203.0.113.50                                    6            0
[ALERT] log_analyzer.sh: Possible brute force attack from 203.0.113.50 (6 failed logins, 0 invalid-user attempts)
Alerts raised: 1
```
*(The report is saved to `/var/log/cybershield/reports/` and deleted after 30 days).*

---

### 5.4 Automated Encrypted Backup (`backup.sh`)

Pulls remote data, encrypts it on-the-fly with AES-256 GPG, verifies checksums, and prunes expired archives.

> [IMPORTANT]
> In a production environment, `backup.sh` connects to dedicated remote servers (e.g., `DB-01` at `192.168.2.10` and `TAS-01` at `192.168.2.20`) over SSH to pull database dumps and threat logs. Since we are running this on a **single virtual machine** without those remote servers, the default configuration IPs will cause SSH connection timeouts. The steps below use **`localhost` (`127.0.0.1`)** as the remote target so that all operations run entirely within the VM.

#### 1. Prepare the VM for Local Backup Testing (One-Time Setup)
Before running `backup.sh`, set up SSH to localhost and create a sample data source:

*1a. Generate an SSH key for root, authorise it for localhost, and trust the host key*
```bash
sudo ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" 2>/dev/null || true
sudo cat /root/.ssh/id_ed25519.pub | sudo tee -a /root/.ssh/authorized_keys > /dev/null
sudo chmod 600 /root/.ssh/authorized_keys
sudo ssh-keyscan -H 127.0.0.1 | sudo tee -a /root/.ssh/known_hosts > /dev/null
sudo chmod 644 /root/.ssh/known_hosts
```

*1b. Create a dummy threat-analysis log directory*
```bash
sudo mkdir -p /var/log/threat-analysis
echo "Threat event detected" | sudo tee /var/log/threat-analysis/sample.log > /dev/null
```

#### 2. Dry-Run Verification (Test Without Modifying Files)
Tests all configuration variables, verifies that the passphrase file exists, checks destination free space, and tests remote SSH connectivity — all against localhost:
```bash
sudo DB_HOST=127.0.0.1 TAS_HOST=127.0.0.1 SSH_USER=root DB_NAME="" backup.sh --dry-run
```
**Sample Output:**
```
2026-10-31 21:14:31 [INFO] backup.sh: Free space in /backup/cybershield: 37515 MB (minimum 1024 MB)
2026-10-31 21:14:31 [INFO] backup.sh: ===== Backup started (encrypt=yes, dry-run=1) =====
2026-10-31 21:14:31 [INFO] backup.sh: DB_NAME is empty: database backup skipped
2026-10-31 21:14:31 [INFO] backup.sh: Backing up logs from 127.0.0.1
2026-10-31 21:14:31 [INFO] backup.sh: DRY-RUN: would create /backup/cybershield/tas_logs_20261031_211431.tar.gz.gpg
2026-10-31 21:14:31 [INFO] backup.sh: Retention: 0 file(s) older than 30 days
2026-10-31 21:14:31 [INFO] backup.sh: ===== Backup finished =====
```

#### 3. Run a Full Local Backup
Execute the backup for real, pointing to localhost and skipping the PostgreSQL dump (no database server on this VM):
```bash
sudo DB_HOST=127.0.0.1 TAS_HOST=127.0.0.1 SSH_USER=root DB_NAME="" backup.sh
```
**Sample Output:**
```
2026-10-31 21:15:53 [INFO] backup.sh: Free space in /backup/cybershield: 37514 MB (minimum 1024 MB)
2026-10-31 21:15:53 [INFO] backup.sh: ===== Backup started (encrypt=yes, dry-run=0) =====
2026-10-31 21:15:53 [INFO] backup.sh: DB_NAME is empty: database backup skipped
2026-10-31 21:15:53 [INFO] backup.sh: Backing up logs from 127.0.0.1
2026-10-31 21:15:53 [INFO] backup.sh: Backup OK: /backup/cybershield/tas_logs_20261031_211553.tar.gz.gpg (4.0K)
2026-10-31 21:15:53 [INFO] backup.sh: Retention: 0 file(s) older than 30 days
2026-10-31 21:15:53 [INFO] backup.sh: ===== Backup finished =====
```

#### 4. Verifying Backup Integrity (`--verify`)
The script includes an automated cryptographic and archive integrity verification option. Pass your actual generated backup file something like "":
```bash
sudo backup.sh --verify /backup/cybershield/<name>
```
**Sample Output:**
```
2026-10-31 21:20:14 [INFO] backup.sh: Checksum OK: tas_logs_20261031_211553.tar.gz.gpg
2026-10-31 21:20:14 [INFO] backup.sh: Content OK: tas_logs_20261031_211553.tar.gz.gpg decrypts and decompresses
```

#### 5. How to Restore from Backup
Backups are encrypted using AES-256 symmetric GPG encryption. Because the passphrase file and backup directory are restricted to `root` (mode 600/700), you must run the restore command with `sudo`:


*Decrypt and list contents of the archive (replace <name >with your actual filename).
Something like tas_logs_20261031_003101.tar.gz.gpg*
```bash
sudo gpg --batch --pinentry-mode loopback --passphrase-file /etc/cybershield/backup.pass \
-d /backup/cybershield/<name> | tar -ztvf -
```

**Sample Output:**
```
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase
drwxr-xr-x root/root         0 2026-10-31 21:14 threat-analysis/
-rw-r--r-- root/root        22 2026-10-31 21:14 threat-analysis/sample.log
```

To actually extract the files into a destination directory (e.g. `/tmp/restore`):
```bash
sudo mkdir -p /tmp/restore
```

*Replace <name> with your actual file name. Something like tas_logs_20261031_003101.tar.gz.gpg*
```bash
sudo gpg --batch --pinentry-mode loopback --passphrase-file /etc/cybershield/backup.pass \
-d /backup/cybershield/<name> | sudo tar -zxvf - -C /tmp/restore
```

**Sample Output:**
```
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase
threat-analysis/
threat-analysis/sample.log
```

---

## 6. Running the Automated Test Suite (`run_tests.sh`)

The automated test suite tests **all 203 test cases** across script syntax, ShellCheck compliance, argument validation, strict mode error traps, and individual script functionality.

### How to Run the Suite
Execute `run_tests.sh` as root, passing the path to the scripts:
```bash
cd ~/CyberShield
sudo ./run_tests.sh .
```

### What Happens During the Test Run
- Creates an isolated testing sandbox under `/tmp/cs`.
- Deploys stubs for network services (`ssh`, `pg_dump`, `mail`, `systemctl`, `journalctl`, `restorecon`, `getenforce`).
- Executes 203 automated assertions (syntax, options, user additions, rollbacks, retention checks, lock checks).
- Outputs the result in `/tmp/cs/results.tsv` and `test_results.txt`.

**Expected Summary:**
```
==================================================
CyberShield Test Results: 203 PASSED, 0 FAILED
==================================================
```

---

## 7. Automated Scheduling (Cron & Logrotate)

To automate routine execution according to enterprise best practices:

### 7.1 Setup Cron Jobs
Create `/etc/cron.d/cybershield`:
```bash
sudo tee /etc/cron.d/cybershield > /dev/null << 'EOF'
# /etc/cron.d/cybershield - Scheduled automation tasks
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin
MAILTO=root

# 1. System Health Monitoring: Every 5 minutes
*/5 * * * *  root  /usr/local/sbin/monitor.sh -q

# 2. Security Log Analysis: Every hour on the hour
0 * * * *    root  /usr/local/sbin/log_analyzer.sh -q

# 3. Off-peak Daily Encrypted Backup: Daily at 02:00 AM
0 2 * * *    root  /usr/local/sbin/backup.sh >> /var/log/cybershield/backup.log 2>&1
EOF
sudo chmod 644 /etc/cron.d/cybershield
```

### 7.2 Setup Log Rotation
Create `/etc/logrotate.d/cybershield`:
```bash
sudo tee /etc/logrotate.d/cybershield > /dev/null << 'EOF'
/var/log/cybershield/*.log /var/log/cybershield/metrics.csv {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
```

---

## 8. Exit Codes Reference

All CyberShield scripts strictly adhere to standardized POSIX exit codes:

| Exit Code | Meaning | Reason |
|---|---|---|
| **`0`** | **Success** | Task completed cleanly with no alerts or issues. |
| **`1`** | **General Failure** | Command failure, caught by `set -Eeuo pipefail` and `ERR` trap with line number. |
| **`2`** | **Bad Usage / Input** | Invalid command-line argument, regex violation, or invalid config value. |
| **`3`** | **Prerequisite Failure** | Missing required tool, unreadable log file, or insecure passphrase permissions. |
| **`4`** | **Privilege Error** | Script was executed without `root` / `sudo` rights. |
| **`5`** | **Security Alert / Finding** | Threshold breached (`monitor.sh`), brute force detected (`log_analyzer.sh`), or audit finding (`user_mgmt.sh audit`). |
| **`6`** | **Lock Collision** | Another instance of the script is already running (`flock`). |

---

## 9. Troubleshooting & FAQ

### Q1: I get `\r: command not found` or `bad interpreter`
* **Cause:** The script was saved or edited in Windows and contains CRLF line endings.
* **Fix:** Run `sed -i 's/\r$//' *.sh` on all scripts in your directory.

### Q2: I get `Run this script as root (use sudo)` (Exit Code 4)
* **Cause:** The script was run as a normal user.
* **Fix:** Prefix the command with `sudo` (e.g., `sudo monitor.sh`). Only `user_mgmt.sh list` does not need root.

### Q3: `sudo user_mgmt.sh` says `command not found`, but it works without `sudo`
* **Cause:** `sudo` uses a restricted `secure_path` (defined in `/etc/sudoers`) that may not include `/usr/local/sbin`, where the scripts are installed.
* **Quick Fix:** Use the full path: `sudo /usr/local/sbin/user_mgmt.sh add alice analyst`.
* **Permanent Fix:** Add `/usr/local/sbin` to sudo's `secure_path`:
  ```bash
  sudo visudo
  ```
  Find the line:
  ```
  Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin
  ```
  Change it to:
  ```
  Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin
  ```
  Save and exit (`:wq`). All `sudo <script>` commands will now resolve correctly.

> **⚠️ Always use `visudo`** to edit the sudoers file — it validates syntax before saving. A broken sudoers file can lock you out of `sudo` entirely.

### Q4: I get `Passphrase file /etc/cybershield/backup.pass must be private` (Exit Code 3)
* **Cause:** File permissions are too loose (e.g., group or others can read it).
* **Fix:** Enforce strict permissions: `sudo chmod 600 /etc/cybershield/backup.pass`.

### Q5: I get `refusing to read /etc/cybershield/cybershield.conf` (Exit Code 3)
* **Cause:** The config file is not owned by root or is writable by other users.
* **Fix:** Run `sudo chown root:root /etc/cybershield/cybershield.conf && sudo chmod 640 /etc/cybershield/cybershield.conf`.

### Q6: I get `Another script is already running` (Exit Code 6)
* **Cause:** A previous instance is still running, or a stale lock file is present in `/run/lock/`.
* **Fix:** Check running instances with `ps aux | grep -E 'backup|monitor|log_analyzer'`. Wait for it to finish or terminate the stuck process.

### Q7: `perms` says `Refusing to change /some/dir (allowed only below ...)`
* **Cause:** `user_mgmt.sh perms` enforces safety boundaries (`ALLOWED_BASES`). It prevents accidental chmod of `/`, `/etc`, or `/usr`.
* **Fix:** Only change directories under `/var/data`, `/srv`, `/opt/cybershield`, or `/home`, or add your path to `ALLOWED_BASES` in `/etc/cybershield/cybershield.conf`.
