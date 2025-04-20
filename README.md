## Overview
Arsenal is a comprehensive penetration testing environment setup script designed to quickly prepare Linux systems for security assessments. This powerful automation tool detects your distribution and installs a carefully curated selection of industry-standard security tools across multiple domains.

## Features
- **Distribution Detection**: Automatically identifies and adapts to major Linux distributions (Debian/Ubuntu, Fedora, Arch, OpenSUSE)
- **WSL Compatibility**: Enhanced functionality when running in Windows Subsystem for Linux
- **Comprehensive Tool Suite**:
  - Network reconnaissance tools
  - Password cracking & brute force utilities
  - Web application security testing
  - Digital forensics
  - Network sniffing & spoofing
  - Encryption & privacy tools
- **Environment Setup**:
  - Python ecosystem with relevant security packages
  - Go environment with latest security tools
  - Organized directory structure for engagement management
- **Operational Security**: Includes thorough cleanup protocol to remove all traces of installation

## Installation
```bash
# Clone the repository
git clone https://github.com/ZeroPvlse/arsenal.git

# Navigate to directory
cd arsenal

# Make script executable
chmod +x setup.sh

# Execute with elevated privileges
sudo ./setup.sh
```

## Installed Components

### Network Reconnaissance
`nmap`, `masscan`, `netcat`, `tcpdump`, `arping`, `hping3`, `dnsutils`, `whois`, `traceroute`, `net-tools`, `wireshark-cli`, `aircrack-ng`, `kismet`

### Password Attacks
`hydra`, `john`, `hashcat`, `crunch`, `wfuzz`, `medusa`, `crowbar`, `theharvester`, `nbtscan`, `enum4linux`

### Web Application Security
`sqlmap`, `gobuster`, `dirb`, `nikto`, `wpscan`, `httrack`, `skipfish`, `whatweb`, `wafw00f`

### Digital Forensics
`binwalk`, `foremost`, `sleuthkit`, `testdisk`, `exiftool`, `autopsy`, `scalpel`

### Network Operations
`tshark`, `ngrep`, `socat`, `telnet`, `wget`, `curl`, `proxychains-ng`, `tor`, `macchanger`, `ethtool`

### Additional Security Tools
`ncat`, `ndiff`, `netdiscover`, `maltego`, `steghide`, `stegosuite`, `ophcrack`, `bettercap`

### Cryptography & Privacy
`gnupg2`, `openssl`, `veracrypt`, `keepassxc`

### Python Environment
Includes `scapy`, `requests`, `beautifulsoup4`, `dnspython`, `pyOpenSSL`, `cryptography`, `impacket`, `paramiko`, `shodan`, `censys`, `awscli`, `crackmapexec`, and other specialized packages.

### Go-based Tools
Includes tools from leading security researchers: `gobuster`, `ffuf`, `subfinder`, `nuclei`, `httpx`, `assetfinder`, `waybackurls`, `gau`, `subjack`, `hakrawler`, `aquatone`, `gowitness`, `Amass`, `naabu`, `puredns`, `kerbrute`

## System Sanitization

To remove all installed components and eliminate operational footprints:

```bash
# Use the built-in alias
sanitize
```

Or execute the cleanup script directly:
```bash
~/pentest/scripts/cleanup.sh
```

The sanitization protocol removes:
- All installed packages and tools
- Directory structures and repositories
- Command history
- System logs
- Temporary files
- SSH known hosts
- Recent file access records

## Legal Disclaimer

This software is provided for authorized security testing and educational purposes only. Usage against systems without explicit permission is illegal and may result in criminal charges. The authors assume no liability for misuse of this toolkit.

## Contribution

Contributions are welcome. Please adhere to professional standards when submitting pull requests, focusing on:
- New tool integration
- Bug fixes
- Performance improvements
- Enhanced compatibility across distributions

---
*Developed by n0_sh4d3*
