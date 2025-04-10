#!/bin/bash

PINK='\033[38;5;219m'
BRIGHT_PINK='\033[38;5;201m'
BLUE='\033[38;5;111m'
BRIGHT_BLUE='\033[38;5;39m'
PURPLE='\033[38;5;183m'
GREEN='\033[38;5;157m'
YELLOW='\033[38;5;227m'
RESET='\033[0m'

echo -e "${BRIGHT_PINK}｡･ﾟ･(ﾉД`)･ﾟ･｡ Hewwo fwend! (≧◡≦) 💕 🌸 ✨${RESET}"
echo -e "${BLUE}Nyaa~! I'm going to make youw computew the most powewful hakku machine evew! ૮ ・ﻌ・ ა 🌟 💻 🔮${RESET}"
echo -e "${PURPLE}Pwepawed by n0_sh4d3 with extwa kawaii powew! (づ￣ ³￣)づ 🎀 🌈 💫${RESET}"

if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="apt install -y"
    UPDATE_CMD="apt update && apt upgrade -y"
    echo -e "${BRIGHT_PINK}Ooooh! Ubuntu/Debian fwendy detected! So cuuuute! (づ｡◕‿‿◕｡)づ 🐧 💝 🍓${RESET}"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD="dnf install -y"
    UPDATE_CMD="dnf update -y"
    echo -e "${BRIGHT_BLUE}Fedowa detected! Tee-hee~ It sounds wike 'fedowa'! *tips hat* m'wady~ (≧ω≦) 🎩 ✨ 🦊${RESET}"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="pacman -S --noconfirm"
    UPDATE_CMD="pacman -Syu --noconfirm"
    echo -e "${PURPLE}Waaaa! Awch Winux! So sophisticated, just wike my senpai! (♡°▽°♡) 🏹 🌙 💜${RESET}"
elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
    INSTALL_CMD="zypper install -y"
    UPDATE_CMD="zypper update -y"
    echo -e "${GREEN}OwOpenSUSE detected! It sounds wike sus~ Amogus! ⊂(・▽・⊂) 🍏 👾 🧩${RESET}"
else
    echo -e "${YELLOW}Oh nyo! (;´Д`) I can't find a package managew-sama! P-pwease install packages manyuawwy, gomenasai!! 😢 📦 🔍${RESET}"
    exit 1
fi

if grep -q Microsoft /proc/version; then
    echo -e "${BRIGHT_PINK}Uwaaaa~! WSL detected! Windows-sama and Linux-kun togethew! So kawaii! ヽ(>∀<☆)ノ 🪟 ❤️ 🐧 💞${RESET}"
    IS_WSL=true
else
    IS_WSL=false
fi

INSTALL_LOG="/tmp/n0_sh4d3_install_log_$(date +%s).txt"
touch $INSTALL_LOG
echo -e "${BRIGHT_BLUE}Cweating a secwet log of evewything we install! Ninja technique! (ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ 🥷 📝 🔐${RESET}" 

echo -e "${PINK}Updating your system! Let's make it shiny and new~! ✨ 🔄 🚀${RESET}"
sudo $UPDATE_CMD 2>&1 | tee -a $INSTALL_LOG

echo -e "${BRIGHT_BLUE}Instawwing devewopment toows! Coding is sugoi desu ne~! (♥ω♥ ) ~♪ 🛠️ 💻 👩‍💻${RESET}"
if [ "$PKG_MANAGER" = "apt" ]; then
    sudo $INSTALL_CMD build-essential 2>&1 | tee -a $INSTALL_LOG
elif [ "$PKG_MANAGER" = "dnf" ]; then
    sudo $INSTALL_CMD @development-tools 2>&1 | tee -a $INSTALL_LOG
elif [ "$PKG_MANAGER" = "pacman" ]; then
    sudo $INSTALL_CMD base-devel 2>&1 | tee -a $INSTALL_LOG
elif [ "$PKG_MANAGER" = "zypper" ]; then
    sudo $INSTALL_CMD -t pattern devel_basis 2>&1 | tee -a $INSTALL_LOG
fi

echo -e "${BRIGHT_PINK}Instawwing netwouk wecon toows! I'm gonna find aww the secwets, nya~! (=^･ω･^=) 🔍 🌐 🐱${RESET}"
NETWORK_TOOLS="nmap masscan netcat tcpdump arping hping3 dnsutils whois traceroute net-tools wireshark-cli aircrack-ng kismet"
sudo $INSTALL_CMD $NETWORK_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$NETWORK_TOOLS" >> $INSTALL_LOG

echo -e "${PURPLE}Instawwing pwetty pwetty hacking toows! Hacku hacku, yay~! ♡〜٩(^▿^)۶〜♡ 🔓 🎮 💜${RESET}"
HACK_TOOLS="hydra john hashcat crunch wfuzz medusa crowbar theharvester nbtscan enum4linux"
sudo $INSTALL_CMD $HACK_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$HACK_TOOLS" >> $INSTALL_LOG

echo -e "${BRIGHT_BLUE}Web appwication testing toows awe so kawaii desu! Let's find those vuwnyewabiwities! (ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ 🕸️ 🔮 🌊${RESET}"
WEB_TOOLS="sqlmap gobuster dirb nikto wpscan httrack skipfish whatweb wafw00f"
sudo $INSTALL_CMD $WEB_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$WEB_TOOLS" >> $INSTALL_LOG

echo -e "${PINK}Fowensics toows awe wike detective wouk! I'm a wittle hakku detective! (⌒▽⌒)♪ 🔍 🕵️‍♀️ 🧪${RESET}"
FORENSIC_TOOLS="binwalk foremost sleuthkit testdisk exiftool autopsy scalpel"
sudo $INSTALL_CMD $FORENSIC_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$FORENSIC_TOOLS" >> $INSTALL_LOG

echo -e "${BRIGHT_PINK}Sniffing and spoofing toows! It's wude not to check all pwotocows~ nya~ Always giving the sewvew wots of attention~ (*≧ω≦) 👃 🦊 📡${RESET}"
SNIFF_TOOLS="tshark ngrep socat telnet wget curl proxychains-ng tor macchanger ethtool"
sudo $INSTALL_CMD $SNIFF_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$SNIFF_TOOLS" >> $INSTALL_LOG

echo -e "${BLUE}Instawwing extwa secuwity toows! Moar tools is moar kawaii! (≧◡≦) ♡ 🔒 ⚔️ 🛡️${RESET}"
EXTRA_TOOLS="ncat ndiff netdiscover maltego steghide stegosuite ophcrack bettercap"
sudo $INSTALL_CMD $EXTRA_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$EXTRA_TOOLS" >> $INSTALL_LOG

echo -e "${PURPLE}Instawwing encryption and privacy toows! Keep ouw secwets safe and kawaii! ⊂(◉‿◉)つ 🔐 🎭 💌${RESET}"
CRYPTO_TOOLS="gnupg2 openssl veracrypt keepassxc"
sudo $INSTALL_CMD $CRYPTO_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$CRYPTO_TOOLS" >> $INSTALL_LOG

echo -e "${BRIGHT_BLUE}Setting up Python enviwonment! Pythwon is such a cutie patootie language, don't you think? ʕ•ᴥ•ʔ 🐍 🧙‍♀️ 🪄${RESET}"
PY_TOOLS="python3-pip python3-dev python3-venv"
sudo $INSTALL_CMD $PY_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$PY_TOOLS" >> $INSTALL_LOG

pip3 install --upgrade pip 2>&1 | tee -a $INSTALL_LOG
PIP_PACKAGES="scapy requests beautifulsoup4 dnspython pyOpenSSL cryptography impacket paramiko shodan censys awscli droopescan crackmapexec ssh-audit trufflehog pwntools pypykatz dsinternals bloodhound"
pip3 install $PIP_PACKAGES 2>&1 | tee -a $INSTALL_LOG
echo "$PIP_PACKAGES" >> $INSTALL_LOG

echo -e "${BRIGHT_PINK}Instawwing Go and Go-based toows! Go is fast wike Sonic-kun! Gotta go fast, nyaa~! (ノ^_^)ノ 🏃‍♂️ 💨 🦔${RESET}"
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
    echo -e "${PINK}Instawwing kawaii Go tool: $tool ヾ(≧▽≦*)o ✨ 🛠️ 🧰${RESET}"
    go install $tool 2>&1 | tee -a $INSTALL_LOG
    echo "$tool" >> $INSTALL_LOG
done

echo -e "${BRIGHT_BLUE}Cweating diwectowy stwuctuwe! Evewything needs a pwetty home, desu~! ヾ(≧▽≦*)o 🏠 📁 🎀${RESET}"
mkdir -p ~/pentest-chan/{tools,wordlists,loot,recon,scripts,exploits,payloads,reports,shells,wireless,privesc}
echo "~/pentest-chan/{tools,wordlists,loot,recon,scripts,exploits,payloads,reports,shells,wireless,privesc}" >> $INSTALL_LOG

echo -e "${BRIGHT_PINK}Downwoading common wowdwists and wesouwces! So many wowds, so kawaii! (●´ω｀●) 📚 📝 💭${RESET}"
GITHUB_REPOS=(
    "https://github.com/danielmiessler/SecLists.git:~/pentest-chan/wordlists/SecLists"
    "https://github.com/swisskyrepo/PayloadsAllTheThings.git:~/pentest-chan/wordlists/PayloadsAllTheThings"
    "https://github.com/carlospolop/PEASS-ng.git:~/pentest-chan/tools/PEASS-ng"
    "https://github.com/lgandx/Responder.git:~/pentest-chan/tools/Responder"
    "https://github.com/PowerShellMafia/PowerSploit.git:~/pentest-chan/tools/PowerSploit"
    "https://github.com/samratashok/nishang.git:~/pentest-chan/tools/nishang"
    "https://github.com/payloadbox/xss-payload-list.git:~/pentest-chan/payloads/xss-payload-list"
    "https://github.com/tennc/webshell.git:~/pentest-chan/shells/webshell"
    "https://github.com/AlessandroZ/LaZagne.git:~/pentest-chan/tools/LaZagne"
    "https://github.com/SecureAuthCorp/impacket.git:~/pentest-chan/tools/impacket"
    "https://github.com/trustedsec/unicorn.git:~/pentest-chan/tools/unicorn"
    "https://github.com/bettercap/bettercap.git:~/pentest-chan/tools/bettercap"
    "https://github.com/s0md3v/XSStrike.git:~/pentest-chan/tools/XSStrike"
    "https://github.com/lanjelot/patator.git:~/pentest-chan/tools/patator"
    "https://github.com/byt3bl33d3r/CrackMapExec.git:~/pentest-chan/tools/CrackMapExec"
    "https://github.com/pentestmonkey/php-reverse-shell.git:~/pentest-chan/shells/php-reverse-shell"
)

for repo in "${GITHUB_REPOS[@]}"; do
    IFS=':' read -r repo_url repo_path <<< "$repo"
    echo -e "${PURPLE}Cwoning $repo_url to $repo_path ✧･ﾟ: *✧･ﾟ:* 🌟 📥 🧚‍♀️${RESET}"
    git clone $repo_url $repo_path 2>&1 | tee -a $INSTALL_LOG
    echo "$repo_url:$repo_path" >> $INSTALL_LOG
done

echo -e "${BRIGHT_BLUE}Instawwing tewminaw pwoductivity toows! Tewminaws need wuv too, nya~! (◕‿◕✿) 💻 ⌨️ 🎨${RESET}"
TERM_TOOLS="tmux htop fzf jq bat neofetch"
sudo $INSTALL_CMD $TERM_TOOLS 2>&1 | tee -a $INSTALL_LOG
echo "$TERM_TOOLS" >> $INSTALL_LOG

echo -e "${PINK}Fixing pewmissions! Evewyone needs the wight access, desu! UwU permissions awe impowtant! (￣ω￣) 🔑 🚪 👮‍♀️${RESET}"
chmod -R 755 ~/pentest-chan/scripts
chmod -R +x ~/pentest-chan/tools

echo -e "${BRIGHT_PINK}Cweating a supew thowough cwean-up scwipt to wemove ouw footpwints! Ninja vanish~! ヾ(･ω･*)ﾉ 🥷 💨 🧹${RESET}"
cat > ~/pentest-chan/scripts/cleanup.sh << 'EOL'
#!/bin/bash

# Define color codes
PINK='\033[38;5;219m'
BRIGHT_PINK='\033[38;5;201m'
BLUE='\033[38;5;111m'
BRIGHT_BLUE='\033[38;5;39m'
PURPLE='\033[38;5;183m'
GREEN='\033[38;5;157m'
YELLOW='\033[38;5;227m'
RESET='\033[0m'

echo -e "${BRIGHT_PINK}｡･ﾟ･(ﾉД`)･ﾟ･｡ n0_sh4d3's cleanup script is wunning! OwO 🧼 🧽 ✨${RESET}"
echo -e "${BLUE}⊂(・﹏・⊂) Oh nyo! Time to say goodbye to all our hakku tools! (ಥ﹏ಥ) 👋 😢 💔${RESET}"

INSTALL_LOG=$(find /tmp -name "n0_sh4d3_install_log_*.txt" | sort | tail -n 1)
if [ -z "$INSTALL_LOG" ]; then
    echo -e "${YELLOW}Can't find install log! (;´Д`) We'll do our best anyway! 📝 🔍 😓${RESET}"
else
    echo -e "${GREEN}Found install log: $INSTALL_LOG, we'll use this to remove everything! (｡•̀ᴗ-)✧ 📋 🔎 ✅${RESET}"
fi

echo -e "${BRIGHT_PINK}Removing all our special pentest-chan tools! Sayonara, tools-kun! (╥_╥) 🧰 👋 🌸${RESET}"
rm -rf ~/pentest-chan
rm -rf ~/.cache/go-build
rm -rf ~/.npm
rm -rf ~/.pyenv
rm -rf ~/.gem
rm -rf ~/.cargo

echo -e "${PURPLE}Uninstalling all the packages we installed! Forgive me packages-sama! (｡•́︿•̀｡) 📦 🗑️ 🙏${RESET}"
if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
else
    echo -e "${YELLOW}Can't find package manager! So embarassing >_< Please clean manually, gomenasai! 😳 🙈 🔧${RESET}"
    exit 1
fi

if [ -f "$INSTALL_LOG" ]; then
    PACKAGES=$(grep -v "github.com" "$INSTALL_LOG" | grep -v "~/" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo -e "${BRIGHT_BLUE}Found these packages to remove: $PACKAGES 📋 🔍 ✂️${RESET}"
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

echo -e "${PINK}Removing Go and all its kawaii fwiends! (ノ°益°)ノ彡┻━┻ 🏃‍♂️ 💨 👋${RESET}"
sudo rm -rf /usr/local/go
rm -rf ~/go
sed -i '/GOPATH/d' ~/.bashrc
sed -i '/export PATH=\$PATH:\$GOPATH\/bin/d' ~/.bashrc

echo -e "${BRIGHT_BLUE}Uninstalling pip packages! Bye-bye python modules! (╯︵╰,) 🐍 📦 💔${RESET}"
if [ -f "$INSTALL_LOG" ]; then
    PIP_PACKAGES=$(grep "pip3 install" "$INSTALL_LOG" | sed 's/pip3 install//g' | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')
    echo -e "${PURPLE}Found these pip packages to remove: $PIP_PACKAGES 📋 🔍 ✂️${RESET}"
else
    PIP_PACKAGES="scapy requests beautifulsoup4 dnspython pyOpenSSL cryptography impacket paramiko shodan censys awscli droopescan crackmapexec ssh-audit trufflehog pwntools pypykatz dsinternals bloodhound"
fi

pip3 uninstall -y $PIP_PACKAGES

if [ "$PKG_MANAGER" = "apt" ]; then
    echo -e "${BRIGHT_PINK}Cleaning apt wists and caches! So fwesh and cwean! (ﾉ´ヮ`)ﾉ*: ･ﾟ 🧹 ✨ 🌈${RESET}"
    sudo rm -rf /var/lib/apt/lists/*
fi

echo -e "${BLUE}Cleaning package managew cache! No more cwumbs! ✧*｡٩(ˊᗜˋ*)و✧*｡ 🍪 🧹 🧽${RESET}"
if [ "$PKG_MANAGER" = "apt" ]; then
    sudo apt clean
elif [ "$PKG_MANAGER" = "dnf" ]; then
    sudo dnf clean all
elif [ "$PKG_MANAGER" = "pacman" ]; then
    sudo pacman -Scc --noconfirm
elif [ "$PKG_MANAGER" = "zypper" ]; then
    sudo zypper clean
fi

echo -e "${PURPLE}Cleaning bash histowy! No twace of our kawaii commands! (⌒‿⌒) 📜 🔍 🙈${RESET}"
cat /dev/null > ~/.bash_history
history -c
history -w

echo -e "${BRIGHT_PINK}Cleaning othew shell histowise too! Suuuper clean! (づ￣ ³￣)づ 🐚 📝 🧽${RESET}"
rm -f ~/.zsh_history ~/.zhistory
rm -f ~/.python_history
rm -f ~/.mysql_history
rm -f ~/.node_repl_history

echo -e "${BRIGHT_BLUE}Cleaning wogs that might have seen our kawaii activities! ( ͡~ ͜ʖ ͡°) 📋 👀 🙊${RESET}"
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

echo -e "${PINK}Cleaning temp fiwes! No more messes! (ノ^_^)ノ 🗑️ 🧹 ✨${RESET}"
sudo rm -rf /tmp/*
sudo rm -f /tmp/.*

echo -e "${PURPLE}Cleaning bash sessions! No remembewing ouw kawaii time togethew! (╯•﹏•╰) 💭 ⏱️ 💔${RESET}"
rm -rf ~/.bash_sessions/

echo -e "${BRIGHT_PINK}Cleaning SSH known hosts! Fowget all the sewvews we visited! (´。＿。｀) 🏠 🔑 💫${RESET}"
rm -f ~/.ssh/known_hosts

echo -e "${BLUE}Destroying our install log! The final evidence is gone! (┬┬﹏┬┬) 📝 🔥 🥷${RESET}"
rm -f $INSTALL_LOG

echo -e "${BRIGHT_BLUE}Cleaning recent files! Like we were never here! ヽ(°〇°)ﾉ 📁 🧙‍♀️ ✨${RESET}"
rm -f ~/.local/share/recently-used.xbel

echo -e "${PURPLE}Making suwe all changes are saved! Flushing all the things! (ﾉ≧∀≦)ﾉ 💾 🌊 🚽${RESET}"
sync

echo -e "${BRIGHT_PINK}Finally removing myself! This is so sad, Alexa play Despacito! (⋟﹏⋞) 🎵 😢 👋${RESET}"
shred -u "$0"

echo -e "${YELLOW}All cleaned up! No trace left behind, just like a kawaii ninja! ♡(￣▽￣♡) 🥷 ✨ 💕${RESET}"
echo -e "${BRIGHT_BLUE}Sayonara, senpai! Hope to see you again soon! (´｡• ᵕ •｡`) ♡ 👋 🌸 💖${RESET}"
EOL

chmod +x ~/pentest-chan/scripts/cleanup.sh
echo "alias cya='~/pentest-chan/scripts/cleanup.sh'" >> ~/.bashrc
echo "alias start='cd ~/pentest-chan && ls -la'" >> ~/.bashrc

echo -e "${BRIGHT_PINK}✧･ﾟ: *✧･ﾟ:* Yaaaay! pentesting enviwonment is weady! *:･ﾟ✧*:･ﾟ✧ 🎉 🌈 🎊${RESET}"
echo -e "${BLUE}You're all set up for hakku time, Senpai! (ﾉ≧∀≦)ﾉ 💖 🔮 🌟${RESET}"
echo -e "${PURPLE}If you need to cweany-weany evewything up, just wun ~/pentest-chan/scripts/cleanup.sh 🧹 🧽 ✨${RESET}"
echo -e "${BRIGHT_PINK}Or use the alias 'cya' for quick access! OwO 👋 💫 🌸${RESET}"
