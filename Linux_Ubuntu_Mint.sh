#!/bin/bash

# Linux Ubuntu/Mint Security Hardening Script
# CyberPatriot Competition

echo "Starting system security hardening..."

# Update and upgrade the system
echo "Updating and upgrading packages..."
sudo apt-get update -y && sudo apt-get upgrade -y

# Disable root login
echo "Disabling root account..."
sudo passwd -l root

# Secure SSH
echo "Securing SSH configuration..."
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Disable guest account (if using lightdm)
if [ -f /etc/lightdm/lightdm.conf ]; then
    echo "Disabling guest account..."
    sudo bash -c 'echo -e "\nallow-guest=false" >> /etc/lightdm/lightdm.conf'
    sudo bash -c 'echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf'
    sudo bash -c 'echo "greeter-show-manual-login=true" >> /etc/lightdm/lightdm.conf'
fi

# Password Policy
echo "Configuring password expiration policy..."
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   30/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   12/' /etc/login.defs

# Enforcing account lockout policy
echo "Enforcing account lockout policy..."
sudo bash -c 'echo "auth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail even_deny_root" >> /etc/pam.d/common-auth'

# Firewall Setup (UFW)
echo "Setting up firewall (UFW)..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable

# Disable unnecessary services (example services)
echo "Disabling unnecessary services..."
sudo systemctl disable cups
sudo systemctl disable bluetooth
sudo systemctl disable avahi-daemon

# Remove unauthorized users
echo "Checking and removing unauthorized users..."
for user in $(awk -F: '{ if ($3 >= 1000 && $1 != "nobody") print $1}' /etc/passwd); do
    if ! id $user > /dev/null 2>&1; then
        echo "Removing unauthorized user: $user"
        sudo userdel -r $user
    fi
done

# Remove unauthorized packages
echo "Removing unnecessary packages..."
sudo apt-get purge -y telnet rsh-server xinetd

# Kernel Hardening (Sysctl)
echo "Applying kernel hardening settings..."
sudo bash -c 'cat <<EOF >> /etc/sysctl.conf
# Disable IP forwarding
net.ipv4.ip_forward = 0
# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
EOF'
sudo sysctl -p

# Remove all sound files (common formats)
echo "Removing all sound files from the system..."
sudo find / -type f \( -iname "*.mp3" -o -iname "*.wav" -o -iname "*.ogg" -o -iname "*.flac" -o -iname "*.aac" \) -exec rm -f {} \;

# Checking for rootkits (Optional: You need to install rkhunter)
if command -v rkhunter >/dev/null 2>&1; then
    echo "Checking for rootkits with rkhunter..."
    sudo rkhunter --checkall --skip-keypress
else
    echo "rkhunter not found. Skipping rootkit check..."
fi

# Checking installed packages and services (Optional)
echo "Verifying repositories and packages..."
sudo apt-cache policy

# Final report
echo "System hardening completed. Please review changes and reboot if necessary."