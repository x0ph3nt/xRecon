#!/bin/bash


# Banner
if command -v figlet >/dev/null 2>&1; then
    figlet "xRecon"
fi
echo "----------------------------------------"


# Check if arguments or a file are provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target-domain-or-ip> [<target2> ...] or $0 -f <targets-file>"
    exit 1
fi

# Set output and tools directories
OUTPUT_DIR="$(pwd)/output"
mkdir -p "$OUTPUT_DIR"

# Function to check dependencies are installed or not
echo "[*] Updating packages..."
sudo apt update -y
check_and_install() {
    local tool="$1"
    if ! command -v "$tool" &> /dev/null; then
        echo "[!] $tool not found. Installing..."

        case "$tool" in
            nmap)
                sudo apt install -y nmap
                ;;
            nikto)
                sudo apt install -y nikto
                ;;
            whois)
                sudo apt install -y whois
                ;;
            nslookup)
                sudo apt install -y dnsutils
                ;;
            nc)
                sudo apt install -y netcat-openbsd
                ;;
            parallel)
                sudo apt install -y parallel
                ;;
            figlet)
                sudo apt install -y figlet 
                ;;
            *)
                echo "[!] Unknown tool: $tool. Please install it manually."
                ;;
        esac
    else
        echo "[+] $tool is already installed"
    fi
}

check_and_install nmap
check_and_install nikto
check_and_install whois
check_and_install nslookup
check_and_install nc
check_and_install parallel
check_and_install figlet


# Function to log messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$OUTPUT_DIR/logs.txt"
}

# Function to log vulnerabilities
log_vulnerability() {
    echo "[VULNERABLE] [$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$OUTPUT_DIR/vulnerabilities.txt"
}

is_ip() {
local ip="$1"
local regex="^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
if [[ $ip =~ $regex ]]; then
	#its an ip
	return 0;
else
	#not an ip
	return 1
fi
}

is_alive() {
    local target="$1"
    log_message "Checking if $target is alive.."

    if is_ip "$target"; then
        # Try ping 
        if ping -c 1 -W 2 "$target" > /dev/null 2>&1; then
            return 0
        fi

        # Try common ports 
        for port in 80 443 22 21 25 3389; do
            if nc -z -w 2 "$target" $port > /dev/null 2>&1; then
                return 0
            fi
        done

        log_message "Host seems down (no ping, no open common ports)"
        return 1

    else
        # domain
        if nslookup "$target" >/dev/null 2>&1; then
            return 0
        else
            log_message "DNS resolution failed for $target"
            return 1
        fi
    fi
}

# Function to check for HTTP/HTTPS services
check_web_services() {
    local nmap_file="$1"

    if grep -Eiq "^[0-9]+/tcp\s+open\s+.*(http|https|ssl/http|http-alt)" "$nmap_file"; then
        return 0  # Web services detected
    else
        return 1  # No web services detected
    fi
}


# Function to check for outdated software versions
check_outdated_versions() {
    local nmap_file="$1"
    local target="$2"

    # Apache (versions < 2.4)
    if grep -Eiq "Apache/?(1\.|2\.[0-3]\.)" "$nmap_file"; then
        log_vulnerability "Potentially outdated Apache detected (<2.4) on $target. Check $nmap_file"
    fi

    # OpenSSH (versions < 7.2)
    if grep -Eiq "OpenSSH[_ ]([0-6]\.|7\.[0-1])" "$nmap_file"; then
        log_vulnerability "Potentially outdated OpenSSH detected (<7.2) on $target. Check $nmap_file"
    fi

    # vsftpd (2.3.x vulnerable)
    if grep -Eiq "vsftpd\s+2\.3\.[0-9]" "$nmap_file"; then
        log_vulnerability "Vulnerable vsftpd 2.3.x detected on $target. Check $nmap_file"
    fi

    # MySQL (versions < 5.5)
    if grep -Eiq "MySQL\s+5\.[0-4]\." "$nmap_file"; then
        log_vulnerability "Potentially outdated MySQL detected (<5.5) on $target. Check $nmap_file"
    fi
}

# Function to parse Nikto output for high/critical vulnerabilities
parse_nikto_output() {
local nikto_file="$1"
local target="$2"

# Check for high/critical vulnerabilities in Nikto output
if grep -q "High" "$nikto_file"; then
    log_vulnerability "High severity vulnerabilities found on $target. Check $nikto_file for details."
fi
if grep -q "Critical" "$nikto_file"; then
    log_vulnerability "Critical severity vulnerabilities found on $target. Check $nikto_file for details."
fi

# Specific checks for common vulnerabilities
if grep -q "X-Frame-Options header is not present" "$nikto_file"; then
    log_vulnerability "Missing X-Frame-Options header on $target. This may allow clickjacking attacks. Check $nikto_file for details."
fi
if grep -q "X-Content-Type-Options header is not set" "$nikto_file"; then
    log_vulnerability "Missing X-Content-Type-Options header on $target. This may allow MIME type sniffing. Check $nikto_file for details."
fi
if grep -q "HTTP TRACE method is active" "$nikto_file"; then
    log_vulnerability "HTTP TRACE method enabled on $target. This may allow Cross-Site Tracing (XST) attacks. Check $nikto_file for details."
fi
if grep -q "phpinfo.php" "$nikto_file"; then
    log_vulnerability "phpinfo.php file exposed on $target. This may leak sensitive information. Check $nikto_file for details."
fi
}

# Function to perform recon on a single target
perform_recon() {
TARGET=$1
SAFE_TARGET=$(echo "$TARGET" | tr '/:' '_')
TARGET_OUTPUT_DIR="$OUTPUT_DIR/$SAFE_TARGET"
mkdir -p "$TARGET_OUTPUT_DIR"

log_message "Starting recon on target: $TARGET"

if ! is_alive "$TARGET"; then
	log_message "$TARGET dead skipping..."
	return 
fi

log_message "Running whois..."
whois "$TARGET" > "$TARGET_OUTPUT_DIR/whois.txt" 2>&1

echo "----------------------------------------"

# Perform nmap scan
log_message "Running nmap on $TARGET"
nmap -Pn -sV -sC -O -T4 "$TARGET" > "$TARGET_OUTPUT_DIR/nmap.txt" 2>&1

echo "----------------------------------------"

# Check for outdated software versions
check_outdated_versions "$TARGET_OUTPUT_DIR/nmap.txt" "$TARGET"

echo "----------------------------------------"

# Check for web services
if check_web_services "$TARGET_OUTPUT_DIR/nmap.txt"; then
    # Perform vulnerability scanning with nikto
    log_message "Performing vulnerability scanning with nikto..."
    nikto -h "$TARGET" > "$TARGET_OUTPUT_DIR/nikto.txt" 2>&1

    # Parse Nikto output for high/critical vulnerabilities
    parse_nikto_output "$TARGET_OUTPUT_DIR/nikto.txt" "$TARGET"
else
    log_message "No HTTP/HTTPS services detected. Skipping web-specific scans."
fi

echo "----------------------------------------"

log_message "Recon completed for target: $TARGET. Results saved in $TARGET_OUTPUT_DIR/"
}
export -f perform_recon log_message log_vulnerability is_ip is_alive check_web_services check_outdated_versions parse_nikto_output
export OUTPUT_DIR


# Main script logic
if [ "$1" = "-f" ]; then
# Read targets from file
if [ ! -f "$2" ]; then
    echo "File $2 not found."
    exit 1
fi
    parallel --jobs 5 --load 80% perform_recon :::: "$2"
else
# Read targets from command line arguments
TARGETS=("$@")
for TARGET in "${TARGETS[@]}"; do
    perform_recon "$TARGET"
done
fi

log_message "All targets processed. Recon completed."
