#!/bin/bash

# ANSI color codes for terminal output
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

echo -e "${RED}[!] TACTICAL PENETRATION TESTING ENVIRONMENT SETUP${RESET}"
echo -e "${BLUE}[+] Developed by n0_sh4d3 ${RESET}"

# Detect package manager
if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="apt install -y"
    UPDATE_CMD="apt update && apt upgrade -y"
    echo -e "${BLUE}[*] Debian/Ubuntu system detected${RESET}"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD="dnf install -y"
    UPDATE_CMD="dnf update -y"
    echo -e "${BLUE}[*] Fedora system detected${RESET}"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="pacman -S --noconfirm"
    UPDATE_CMD="pacman -Syu --noconfirm"
    echo -e "${BLUE}[*] Arch Linux system detected${RESET}"
elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
    INSTALL_CMD="zypper install -y"
    UPDATE_CMD="zypper update -y"
    echo -e "${BLUE}[*] OpenSUSE system detected${RESET}"
else
    echo -e "${RED}[!] ERROR: No compatible package manager found. Manual installation required.${RESET}"
    exit 1
fi

# Check for WSL
if grep -q Microsoft /proc/version; then
    echo -e "${YELLOW}[*] WSL environment detected${RESET}"
    IS_WSL=true
else
    IS_WSL=false
fi

# Create installation log
INSTALL_LOG="/tmp/pentest_install_log_$(date +%s).txt"
touch $INSTALL_LOG
echo -e "${BLUE}[+] Creating installation log at $INSTALL_LOG${RESET}"

echo -e "${GREEN}[*] Updating system packages${RESET}"
sudo $UPDATE_CMD 2>&1 | tee -a $INSTALL_LOG

echo -e "${CYAN}[*] Installing development tools${RESET}"
if [ "$PKG_MANAGER" = "apt" ]; then
    sudo $INSTALL_CMD build-essential 2>&1 | tee -a $INSTALL_LOG
elif [ "$PKG_MANAGER" = "dnf" ]; then
    sudo $INSTALL_CMD @development-tools 2>&1 | tee -a $INSTALL_LOG
elif [ "$PKG_MANAGER" = "pacman" ]; then
    sudo $INSTALL_CMD base-devel 2>&1 | tee -a $INSTALL_LOG
elif [ "$PKG_MANAGER" = "zypper" ]; then
    sudo $INSTALL_CMD -t pattern devel_basis 2>&1 | tee -a $INSTALL_LOG
fi

echo -e "${YELLOW}[*] Installing network reconnaissance tools${RESET}"
NETWORK_TOOLS="nmap masscan netcat tcpdump arping hping3 dnsutils whois traceroute net-tools wireshark-cli aircrack-ng kismet"
sudo $INSTALL_CMD $NETWORK_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$NETWORK_TOOLS" >> $INSTALL_LOG

echo -e "${RED}[*] Installing password cracking and brute force tools${RESET}"
HACK_TOOLS="hydra john hashcat crunch wfuzz medusa crowbar theharvester nbtscan enum4linux"
sudo $INSTALL_CMD $HACK_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$HACK_TOOLS" >> $INSTALL_LOG

echo -e "${PURPLE}[*] Installing web application testing tools${RESET}"
WEB_TOOLS="sqlmap gobuster dirb nikto wpscan httrack skipfish whatweb wafw00f"
sudo $INSTALL_CMD $WEB_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$WEB_TOOLS" >> $INSTALL_LOG

echo -e "${BLUE}[*] Installing digital forensics tools${RESET}"
FORENSIC_TOOLS="binwalk foremost sleuthkit testdisk exiftool autopsy scalpel"
sudo $INSTALL_CMD $FORENSIC_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$FORENSIC_TOOLS" >> $INSTALL_LOG

echo -e "${GREEN}[*] Installing sniffing and spoofing tools${RESET}"
SNIFF_TOOLS="tshark ngrep socat telnet wget curl proxychains-ng tor macchanger ethtool"
sudo $INSTALL_CMD $SNIFF_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$SNIFF_TOOLS" >> $INSTALL_LOG

echo -e "${CYAN}[*] Installing additional security tools${RESET}"
EXTRA_TOOLS="ncat ndiff netdiscover maltego steghide stegosuite ophcrack bettercap"
sudo $INSTALL_CMD $EXTRA_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$EXTRA_TOOLS" >> $INSTALL_LOG

echo -e "${YELLOW}[*] Installing encryption and privacy tools${RESET}"
CRYPTO_TOOLS="gnupg2 openssl veracrypt keepassxc"
sudo $INSTALL_CMD $CRYPTO_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$CRYPTO_TOOLS" >> $INSTALL_LOG

echo -e "${RED}[*] Setting up Python environment${RESET}"
PY_TOOLS="python3-pip python3-dev python3-venv"
sudo $INSTALL_CMD $PY_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$PY_TOOLS" >> $INSTALL_LOG

pip3 install --upgrade pip 2>&1 | tee -a $INSTALL_LOG
PIP_PACKAGES="scapy requests beautifulsoup4 dnspython pyOpenSSL cryptography impacket paramiko shodan censys awscli droopescan crackmapexec ssh-audit trufflehog pwntools pypykatz dsinternals bloodhound"
pip3 install $PIP_PACKAGES 2>&1 | tee -a $INSTALL_LOG
echo "$PIP_PACKAGES" >> $INSTALL_LOG

echo -e "${PURPLE}[*] Installing Go and Go-based tools${RESET}"
if [ "$PKG_MANAGER" = "apt" ]; then
    sudo $INSTALL_CMD golang-go 2>&1 | tee -a $INSTALL_LOG
    echo "golang-go" >> $INSTALL_LOG
else
    sudo $INSTALL_CMD go 2>&1 | tee -a $INSTALL_LOG
    echo "go" >> $INSTALL_LOG
fi

echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

GO_TOOLS=(
    "github.com/OJ/gobuster/v3@latest"
    "github.com/ffuf/ffuf@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau@latest"
    "github.com/haccer/subjack@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/michenriksen/aquatone@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/OWASP/Amass/v3/...@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/ropnop/kerbrute@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    echo -e "${BLUE}[*] Installing Go tool: $tool${RESET}"
    go install $tool 2>&1 | tee -a $INSTALL_LOG
    echo "$tool" >> $INSTALL_LOG
done

echo -e "${GREEN}[*] Creating directory structure${RESET}"
mkdir -p ~/pentest/{tools,wordlists,loot,recon,scripts,exploits,payloads,reports,shells,wireless,privesc}
echo "~/pentest/{tools,wordlists,loot,recon,scripts,exploits,payloads,reports,shells,wireless,privesc}" >> $INSTALL_LOG

echo -e "${CYAN}[*] Downloading common wordlists and resources${RESET}"
GITHUB_REPOS=(
    "https://github.com/danielmiessler/SecLists.git:~/pentest/wordlists/SecLists"
    "https://github.com/swisskyrepo/PayloadsAllTheThings.git:~/pentest/wordlists/PayloadsAllTheThings"
    "https://github.com/carlospolop/PEASS-ng.git:~/pentest/tools/PEASS-ng"
    "https://github.com/lgandx/Responder.git:~/pentest/tools/Responder"
    "https://github.com/PowerShellMafia/PowerSploit.git:~/pentest/tools/PowerSploit"
    "https://github.com/samratashok/nishang.git:~/pentest/tools/nishang"
    "https://github.com/payloadbox/xss-payload-list.git:~/pentest/payloads/xss-payload-list"
    "https://github.com/tennc/webshell.git:~/pentest/shells/webshell"
    "https://github.com/AlessandroZ/LaZagne.git:~/pentest/tools/LaZagne"
    "https://github.com/SecureAuthCorp/impacket.git:~/pentest/tools/impacket"
    "https://github.com/trustedsec/unicorn.git:~/pentest/tools/unicorn"
    "https://github.com/bettercap/bettercap.git:~/pentest/tools/bettercap"
    "https://github.com/s0md3v/XSStrike.git:~/pentest/tools/XSStrike"
    "https://github.com/lanjelot/patator.git:~/pentest/tools/patator"
    "https://github.com/byt3bl33d3r/CrackMapExec.git:~/pentest/tools/CrackMapExec"
    "https://github.com/pentestmonkey/php-reverse-shell.git:~/pentest/shells/php-reverse-shell"
)

for repo in "${GITHUB_REPOS[@]}"; do
    IFS=':' read -r repo_url repo_path <<< "$repo"
    echo -e "${YELLOW}[*] Cloning $repo_url to $repo_path${RESET}"
    git clone $repo_url $repo_path 2>&1 | tee -a $INSTALL_LOG
    echo "$repo_url:$repo_path" >> $INSTALL_LOG
done

echo -e "${RED}[*] Installing terminal productivity tools${RESET}"
TERM_TOOLS="tmux htop fzf jq bat neofetch"
sudo $INSTALL_CMD $TERM_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$TERM_TOOLS" >> $INSTALL_LOG

echo -e "${PURPLE}[*] Setting appropriate permissions${RESET}"
chmod -R 755 ~/pentest/scripts
chmod -R +x ~/pentest/tools

echo -e "${BLUE}[*] Creating cleanup script${RESET}"
cat > ~/pentest/scripts/cleanup.sh << 'EOL'
#!/bin/bash

# Define color codes
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

echo -e "${RED}[!] EXECUTING FORENSIC COUNTERMEASURES${RESET}"
echo -e "${BLUE}[+] n0_sh4d3's system cleanup protocol initiated${RESET}"

INSTALL_LOG=$(find /tmp -name "pentest_install_log_*.txt" | sort | tail -n 1)
if [ -z "$INSTALL_LOG" ]; then
    echo -e "${YELLOW}[!] Install log not found. Executing standard cleanup protocol.${RESET}"
else
    echo -e "${GREEN}[+] Found install log: $INSTALL_LOG - Using for targeted removal${RESET}"
fi

echo -e "${RED}[*] Removing all pentest tools and directories${RESET}"
rm -rf ~/pentest
rm -rf ~/.cache/go-build
rm -rf ~/.npm
rm -rf ~/.pyenv
rm -rf ~/.gem
rm -rf ~/.cargo

echo -e "${PURPLE}[*] Uninstalling installed packages${RESET}"
if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
else
    echo -e "${YELLOW}[!] Package manager not found. Manual cleanup required.${RESET}"
    exit 1
fi

if [ -f "$INSTALL_LOG" ]; then
    PACKAGES=$(grep -v "github.com" "$INSTALL_LOG" | grep -v "~/" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo -e "${BLUE}[*] Targeted package removal: $PACKAGES${RESET}"
else
    PACKAGES="nmap masscan netcat tcpdump arping hping3 dnsutils whois traceroute net-tools wireshark-cli aircrack-ng kismet hydra john hashcat crunch wfuzz medusa crowbar theharvester nbtscan enum4linux sqlmap gobuster dirb nikto wpscan httrack skipfish whatweb wafw00f binwalk foremost sleuthkit testdisk exiftool autopsy scalpel tshark ngrep socat telnet wget curl proxychains-ng tor macchanger ethtool ncat ndiff netdiscover maltego steghide stegosuite ophcrack bettercap gnupg2 openssl veracrypt keepassxc python3-pip python3-dev python3-venv tmux htop fzf jq bat neofetch golang-go"
fi

if [ "$PKG_MANAGER" = "apt" ]; then
    sudo apt purge -y $PACKAGES
    sudo apt autoremove -y
    sudo apt clean
elif [ "$PKG_MANAGER" = "dnf" ]; then
    sudo dnf remove -y $PACKAGES
    sudo dnf autoremove -y
    sudo dnf clean all
elif [ "$PKG_MANAGER" = "pacman" ]; then
    sudo pacman -Rns --noconfirm $PACKAGES
    sudo pacman -Scc --noconfirm
elif [ "$PKG_MANAGER" = "zypper" ]; then
    sudo zypper remove -y $PACKAGES
    sudo zypper clean
fi

echo -e "${GREEN}[*] Removing Go installation and environment${RESET}"
sudo rm -rf /usr/local/go
rm -rf ~/go
sed -i '/GOPATH/d' ~/.bashrc
sed -i '/export PATH=\$PATH:\$GOPATH\/bin/d' ~/.bashrc

echo -e "${BLUE}[*] Uninstalling pip packages${RESET}"
if [ -f "$INSTALL_LOG" ]; then
    PIP_PACKAGES=$(grep "pip3 install" "$INSTALL_LOG" | sed 's/pip3 install//g' | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')
    echo -e "${PURPLE}[*] Targeted pip package removal: $PIP_PACKAGES${RESET}"
else
    PIP_PACKAGES="scapy requests beautifulsoup4 dnspython pyOpenSSL cryptography impacket paramiko shodan censys awscli droopescan crackmapexec ssh-audit trufflehog pwntools pypykatz dsinternals bloodhound"
fi

pip3 uninstall -y $PIP_PACKAGES

if [ "$PKG_MANAGER" = "apt" ]; then
    echo -e "${RED}[*] Cleaning apt lists and caches${RESET}"
    sudo rm -rf /var/lib/apt/lists/*
fi

echo -e "${CYAN}[*] Purging package manager cache${RESET}"
if [ "$PKG_MANAGER" = "apt" ]; then
    sudo apt clean
elif [ "$PKG_MANAGER" = "dnf" ]; then
    sudo dnf clean all
elif [ "$PKG_MANAGER" = "pacman" ]; then
    sudo pacman -Scc --noconfirm
elif [ "$PKG_MANAGER" = "zypper" ]; then
    sudo zypper clean
fi

echo -e "${PURPLE}[*] Sanitizing bash history${RESET}"
cat /dev/null > ~/.bash_history
history -c
history -w

echo -e "${YELLOW}[*] Removing shell history files${RESET}"
rm -f ~/.zsh_history ~/.zhistory
rm -f ~/.python_history
rm -f ~/.mysql_history
rm -f ~/.node_repl_history

echo -e "${BLUE}[*] Clearing system logs${RESET}"
if [ "$PKG_MANAGER" = "apt" ]; then
    sudo rm -f /var/log/apt/*
    sudo rm -f /var/log/alternatives.log
fi
sudo rm -f /var/log/auth.log*
sudo rm -f /var/log/syslog*
sudo rm -f /var/log/messages*
sudo rm -f /var/log/kern.log*
sudo rm -f /var/log/dpkg.log*
sudo rm -f /var/log/daemon.log*

echo -e "${GREEN}[*] Clearing temporary files${RESET}"
sudo rm -rf /tmp/*
sudo rm -f /tmp/.*

echo -e "${CYAN}[*] Removing bash sessions${RESET}"
rm -rf ~/.bash_sessions/

echo -e "${RED}[*] Clearing SSH known hosts${RESET}"
rm -f ~/.ssh/known_hosts

echo -e "${BLUE}[*] Destroying installation log${RESET}"
rm -f $INSTALL_LOG

echo -e "${PURPLE}[*] Clearing recent files${RESET}"
rm -f ~/.local/share/recently-used.xbel

echo -e "${YELLOW}[*] Executing sync to ensure all changes are written${RESET}"
sync

echo -e "${RED}[*] Self-destructing cleanup script${RESET}"
echo -e "${GREEN}[+] Cleanup protocol complete${RESET}"
echo -e "${BLUE}[+] Forensic counter-measures executed successfully${RESET}"
echo -e "${PURPLE}===========================================${RESET}"
echo -e "${CYAN}YOUR PROOF OF CONCEPT IS OUR POSTMORTEM${RESET}"
echo -e "${PURPLE}===========================================${RESET}"

shred -u "$0"
EOL

chmod +x ~/pentest/scripts/cleanup.sh
echo "alias sanitize='~/pentest/scripts/cleanup.sh'" >> ~/.bashrc
echo "alias arsenal='cd ~/pentest && ls -la'" >> ~/.bashrc

echo -e "${RED}[+] PENETRATION TESTING ENVIRONMENT SETUP COMPLETE${RESET}"
echo -e "${BLUE}[*] Environment is ready for engagement${RESET}"
echo -e "${YELLOW}[*] To execute complete system sanitization, run ~/pentest/scripts/cleanup.sh${RESET}"
echo -e "${GREEN}[*] Or use the alias 'sanitize' for quick access${RESET}"
