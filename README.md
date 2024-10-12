# CyberPatriot Comprehensive Security Checklist

This document serves as a detailed guide to hardening both Linux and Windows systems for the CyberPatriot competition. It includes checklists and scripts to help secure various platforms.

---

## Table of Contents
1. [Windows Checklist](#windows-checklist)
2. [Linux Checklist](#linux-checklist)
3. [Scripts](#scripts)
4. [References](#references)

---

## Windows Checklist

### High-Level Overview
- **Start Downloading Important Service Packs and Windows Updates**  
  *(Do not restart until later)*
- **Look for alternatives to default applications**  
  *e.g., Install Firefox*
- **Install and maintain malware protection software**  
  *e.g., MalWare (Defender), Microsoft Security Essentials*
- **Uninstall Dangerous Software**
  
### Account Management
- Remove guest user
- Remove old or unauthorized accounts
- Ensure all accounts use strong passwords

### Security Settings
- **Account & Local Policies**  
  *Configure password and lockout policies through `secpol.msc`*
- **Action Center**  
  *Resolve pending issues*
- **Windows Firewall**  
  *Configure rules for both inbound and outbound connections*
  
### Services
- Disable unnecessary services like:
  - IIS
  - Telnet
  - Web Services
  - FTP

### Files & Permissions
- Delete suspicious or unauthorized files  
  *(Document the names and locations of deleted files)*

### Configure System Startup
- **Task Scheduler & Task Manager**  
  *Monitor performance, resource usage, and scheduled tasks*
  
### Restart Windows Update  
*(Once initial configuration and securing are complete)*

---

## Basic Security Checklist – Windows 10
- **Advanced Menu**  
  Access via `Windows + X` or right-click the Start menu.
  
### Users and Groups
- Use **Computer Management** (not Users applet)
- Disable unnecessary accounts and ensure all accounts have strong passwords.
- Prevent auto-login using `netplwiz`.
  
### Unauthorized Software
- Check **Start Menu**, **Control Panel -> Programs**, **msconfig.exe**, and **Startup Folder** for unnecessary or unauthorized software.

### Malware Protection
- Install antivirus and antimalware solutions (e.g., **MalwareBytes**)
  
### Updates
- **Windows Update**  
  *Ensure it's set to automatic updates; metered connection can prevent updates.*

### Local Security Policy
- Set **password length**, **complexity**, and **history** through `secpol.msc`.
  
### Auditing & Logging
- Monitor **Event Viewer** for suspicious activities and cleared logs.

### Additional Tools
- Install tools like **CCleaner**, **WinPatrol**, and **MBSA** for system hardening.

---

## Windows Server Checklist

### Internet Explorer Configuration
- Disable **IE Enhanced Security Configuration** through **Server Manager**.
  
### Malware and Rootkits
- Install antivirus and antimalware solutions (e.g., **ClamAV** or trial versions compatible with your OS).
  
### Account Management
- Follow same guidelines as Windows 10: Disable extra accounts, enforce password policies, and prevent auto-login.
  
### Unauthorized Software & Services
- **Check for unnecessary startup services** and **shared files** through **Computer Management** and **MMC**.
  
### Firewall
- Check rules and ensure the firewall is enabled for all profiles.

### Event Logs
- **Monitor Event Logs** (especially the Security Log) for out-of-the-ordinary activities.
  
---

## Linux Checklist

### Account Configuration
- Lock the `root` account:  
  ```bash
  passwd -l root
  ```
- Disable the guest account in `/etc/lightdm/lightdm.conf`:
  ```bash
  allow-guest=false
  greeter-hide-users=true
  greeter-show-manual-login=true
  autologin-user=none
  ```
- Compare `/etc/passwd` and `/etc/group` to remove unauthorized users:
  ```bash
  userdel -r $user
  groupdel $user
  ```

### Password Policy
- Change password expiration requirements in `/etc/login.defs`:
  ```bash
  PASS_MAX_DAYS 30
  PASS_MIN_DAYS 7
  PASS_WARN_AGE 12
  ```
- Enforce account lockout policy in `/etc/pam.d/common-auth`:
  ```bash
  auth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail even_deny_root
  ```

### Network Security
- Enable and configure UFW:
  ```bash
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow $port/service
  ufw enable
  ```
  
### Package Management
- Verify repositories:
  ```bash
  apt-cache policy
  apt-key list
  ```
- Install security updates:
  ```bash
  apt-get update && apt-get upgrade
  ```
  
### Service Hardening
- Configure SSH in `/etc/ssh/sshd_config`:
  ```bash
  PermitRootLogin no
  PasswordAuthentication no
  ChallengeResponseAuthentication no
  UsePAM no
  ```

### Cron Jobs
- Check and clean up cron jobs:
  ```bash
  crontab -e
  crontab -u $user -l
  echo "ALL" >> /etc/cron.deny
  ```

### Kernel Hardening
- Harden kernel settings in `/etc/sysctl.conf`:
  ```bash
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.all.secure_redirects = 0
  net.ipv4.conf.all.log_martians = 1
  ```

---

## Scripts

### Linux_Ubuntu_Mint.sh
A script designed to automate Linux security tasks. **Note:** This script requires further testing and development.
  
### Windows_Hardening.bat
Automates basic Windows security hardening tasks but still requires manual checklist verification.

---
