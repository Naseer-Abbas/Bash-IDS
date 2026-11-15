#!/usr/bin/env bash

# Bash Intrusion Detection System
# Watches authentication logs in real time, scores source IPs inside a
# sliding time window, raises alerts and can block attackers with iptables.
# Run with --demo to see it work against simulated attacks (no root needed).

# Location of this script, so the config is always read from the same folder
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/project.conf"

# Default settings (override any of these in project.conf)
LOG_FILE="auto"            # auto, journal, or a path such as /var/log/auth.log
ALERT_THRESHOLD=3          # events from one IP inside TIME_WINDOW before an alert
BLOCK_THRESHOLD=5          # events from one IP inside TIME_WINDOW before a block
TIME_WINDOW=600            # seconds (10 minutes)
ENABLE_BLOCKING=1          # 1 = block with iptables, 0 = alert only
ALERT_EMAIL=""             # leave empty to disable email alerts
REPORT_INTERVAL=300        # seconds between summary reports
STATE_DIR="/var/log/ids"   # where the IDS writes its own logs
PATTERNS=("failed password" "authentication failure" "invalid user" "sql injection" "xss")
HIGH_RISK_PATTERNS=("accepted password for root" "accepted publickey for root" "password changed" "new user:" "incorrect password attempts")
IGNORE_IPS=("127.0.0.1")
DEMO_MODE=0

# Terminal colours
RED_BG="\e[41m"; YELLOW_BG="\e[43m"; BLUE_BG="\e[44m"
BOLD="\e[1m"; GREEN="\e[1;92m"; PURPLE="\e[1;35m"; ORANGE="\e[1;93m"; ERROR="\e[1;91m"; RESET="\e[0m"

# Rule tag, so the IDS only ever lists or removes its own firewall rules
RULE_TAG="bash-ids"

# Runtime state (kept in memory while the IDS runs)
declare -A EVENT_TIMES     # ip -> space-separated epoch times of recent events
declare -A TOTAL_EVENTS    # ip -> total events seen since start
declare -A ALERTED_AT      # ip -> time of the last threshold alert
declare -A BLOCKED         # ip -> 1 once blocked
DEMO_PID=""
DEMO_DIR=""
EVENT_COUNT=0

usage() {
    cat <<EOF
Usage: sudo $0 [option]

  (no option)        Monitor logs in real time
  --demo             Run against simulated attacks (no root needed, nothing is blocked)
  --list-blocked     Show IPs currently blocked by this IDS
  --unblock IP       Remove the block for one IP
  -h, --help         Show this help

Settings are read from ${CONFIG_FILE} if it exists (see project.conf.example).
EOF
}

# Load project.conf only if it is owned by root or the current user and is not world-writable
load_config() {
    [[ -f "$CONFIG_FILE" ]] || { echo "Using default configuration (copy project.conf.example to project.conf to customise)"; return; }

    local owner perms
    owner=$(stat -c %u "$CONFIG_FILE")
    perms=$(stat -c %a "$CONFIG_FILE")
    if [[ "$owner" != "0" && "$owner" != "$EUID" ]] || (( 8#$perms & 0002 )); then
        echo -e "${ERROR}Refusing to load $CONFIG_FILE: it must be owned by root or you, and not writable by others.${RESET}"
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    echo "Loaded configuration from $CONFIG_FILE"
}

# Find the authentication log for this system
detect_auth_log() {
    local log
    for log in /var/log/auth.log /var/log/secure; do
        [[ -r "$log" ]] && { echo "$log"; return; }
    done
    command -v journalctl &>/dev/null && { echo "journal"; return; }
    for log in /var/log/syslog /var/log/messages; do
        [[ -r "$log" ]] && { echo "$log"; return; }
    done
    echo "none"
}

# Decide which log source to watch, respecting the LOG_FILE setting
resolve_log_source() {
    case "$LOG_FILE" in
        auto)    LOG_FILE=$(detect_auth_log) ;;
        journal) command -v journalctl &>/dev/null || LOG_FILE="none" ;;
        *)       [[ -r "$LOG_FILE" ]] || LOG_FILE="none" ;;
    esac

    if [[ "$LOG_FILE" == "none" ]]; then
        echo -e "${ERROR}ERROR: No readable log source found.${RESET}"
        echo "Options:"
        echo "  1. Set LOG_FILE=\"/path/to/auth.log\" in $CONFIG_FILE"
        echo "  2. Set LOG_FILE=\"journal\" to read the systemd journal"
        echo "  3. Try the demo: $0 --demo"
        exit 1
    fi
}

# Add this machine's own IPv4 addresses to the ignore list so it never blocks itself
ignore_own_addresses() {
    local addr
    if command -v hostname &>/dev/null; then
        for addr in $(hostname -I 2>/dev/null); do
            [[ "$addr" == *.* ]] && IGNORE_IPS+=("$addr")
        done
    fi
}

# Write a timestamped line to the IDS log
log_event() {
    echo "$(date '+%F %T') $*" >> "${STATE_DIR}/ids.log" 2>/dev/null
}

# Send an email alert if ALERT_EMAIL is set and mail is installed
send_alert() {
    local subject=$1 body=$2
    if [[ -n "$ALERT_EMAIL" ]] && command -v mail &>/dev/null; then
        printf '%b\n' "$body" | mail -s "$subject" "$ALERT_EMAIL"
    fi
}

# Return success if the line contains one of the given patterns (case-insensitive)
matches_any() {
    local line=$1 pattern
    shift
    for pattern in "$@"; do
        [[ "$line" == *"$pattern"* ]] && return 0
    done
    return 1
}

# Print the first valid IPv4 address in the line, if any
extract_ip() {
    local line=$1 regex='(^|[^0-9.])(([0-9]{1,3}\.){3}[0-9]{1,3})($|[^0-9.])'
    [[ "$line" =~ $regex ]] || return 1

    local ip=${BASH_REMATCH[2]} octet
    IFS=. read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || return 1
    done
    echo "$ip"
}

is_ignored() {
    local ip=$1 ignored
    for ignored in "${IGNORE_IPS[@]}"; do
        [[ "$ip" == "$ignored" ]] && return 0
    done
    return 1
}

# Record an event for an IP; sets EVENT_COUNT to its number of events inside the time window
record_event() {
    local ip=$1 now=$2 cutoff=$(( $2 - TIME_WINDOW )) recent="" t count=1
    for t in ${EVENT_TIMES[$ip]:-}; do
        if (( t >= cutoff )); then
            recent+="$t "
            count=$(( count + 1 ))
        fi
    done
    EVENT_TIMES[$ip]="${recent}${now}"
    TOTAL_EVENTS[$ip]=$(( ${TOTAL_EVENTS[$ip]:-0} + 1 ))
    EVENT_COUNT=$count
}

# Block an IP with iptables (simulated in demo mode)
block_ip() {
    local ip=$1 count=$2
    [[ -n "${BLOCKED[$ip]:-}" ]] && return
    BLOCKED[$ip]=1

    if (( DEMO_MODE )); then
        echo -e "${RED_BG}BLOCK (simulated):${RESET} $ip - $count events in $(( TIME_WINDOW / 60 )) min"
    elif (( ENABLE_BLOCKING )); then
        if ! iptables -C INPUT -s "$ip" -m comment --comment "$RULE_TAG" -j DROP &>/dev/null; then
            iptables -I INPUT 1 -s "$ip" -m comment --comment "$RULE_TAG" -j DROP
        fi
        echo -e "${RED_BG}BLOCKED:${RESET} $ip - $count events in $(( TIME_WINDOW / 60 )) min"
    else
        echo -e "${RED_BG}WOULD BLOCK (blocking disabled):${RESET} $ip"
    fi

    echo "$(date '+%F %T') $ip" >> "${STATE_DIR}/blocked_ips.log" 2>/dev/null
    log_event "BLOCK $ip ($count events in window)"
    send_alert "IDS: blocked $ip" "Blocked IP: $ip\nEvents in the last ${TIME_WINDOW}s: $count"
}

# Check one log line against the detection rules
analyze_line() {
    local line=$1 ip now count
    ip=$(extract_ip "$line") || ip=""
    [[ -n "$ip" ]] && is_ignored "$ip" && return

    # High-risk events are reported even without an IP (for example sudo failures)
    if matches_any "$line" "${HIGH_RISK_PATTERNS[@]}"; then
        echo -e "${RED_BG}HIGH RISK:${RESET} $line"
        log_event "HIGH RISK: $line"
        send_alert "IDS: high-risk event" "Event: $line"
        return
    fi

    matches_any "$line" "${PATTERNS[@]}" || return

    if [[ -z "$ip" ]]; then
        echo -e "${YELLOW_BG}SUSPICIOUS:${RESET} $line"
        log_event "SUSPICIOUS (no IP): $line"
        return
    fi

    now=$(date +%s)
    record_event "$ip" "$now"
    count=$EVENT_COUNT
    echo -e "${YELLOW_BG}SUSPICIOUS:${RESET} $line ${BOLD}[$ip: $count in window]${RESET}"
    log_event "SUSPICIOUS $ip ($count in window): $line"

    if (( count >= BLOCK_THRESHOLD )); then
        block_ip "$ip" "$count"
    elif (( count >= ALERT_THRESHOLD )) && (( now - ${ALERTED_AT[$ip]:-0} >= TIME_WINDOW )); then
        ALERTED_AT[$ip]=$now
        echo -e "${ORANGE}ALERT:${RESET} $ip reached $count events (block at $BLOCK_THRESHOLD)"
        log_event "ALERT $ip ($count events in window)"
        send_alert "IDS: repeated suspicious activity from $ip" "IP: $ip\nEvents in the last ${TIME_WINDOW}s: $count"
    fi
}

# Print a summary of the top offenders and recent blocks
generate_report() {
    echo -e "\n${BLUE_BG}==== SECURITY REPORT ($(date '+%F %T')) ====${RESET}"

    if (( ${#TOTAL_EVENTS[@]} )); then
        echo -e "\n${BOLD}Top source IPs:${RESET}"
        local ip
        for ip in "${!TOTAL_EVENTS[@]}"; do
            echo "$ip ${TOTAL_EVENTS[$ip]}"
        done | sort -k2 -nr | head -5 | awk '{printf "  %-15s %3d events\n", $1, $2}'
    else
        echo -e "\nNo suspicious IPs seen yet"
    fi

    if [[ -s "${STATE_DIR}/blocked_ips.log" ]]; then
        echo -e "\n${BOLD}Recently blocked:${RESET}"
        tail -3 "${STATE_DIR}/blocked_ips.log" | awk '{print "  " $NF " (" $1 " " $2 ")"}'
    fi

    echo -e "\n${BOLD}Monitoring:${RESET} $LOG_FILE"
    echo -e "${BOLD}Rules:${RESET} ${#PATTERNS[@]} suspicious, ${#HIGH_RISK_PATTERNS[@]} high-risk | window ${TIME_WINDOW}s | alert ${ALERT_THRESHOLD} | block ${BLOCK_THRESHOLD}\n"
}

# Write realistic fake log lines from a small pool of attacker IPs
# (RFC 5737 documentation addresses, so they can never be real hosts)
start_demo() {
    DEMO_DIR=$(mktemp -d /tmp/ids_demo.XXXXXX)
    LOG_FILE="${DEMO_DIR}/auth.log"
    STATE_DIR="${DEMO_DIR}/state"
    touch "$LOG_FILE"

    local parent=$$
    (
        attackers=("203.0.113.10" "198.51.100.23" "192.0.2.77")
        # Stop by itself if the IDS is no longer running
        while kill -0 "$parent" 2>/dev/null; do
            ip=${attackers[RANDOM % ${#attackers[@]}]}
            ts=$(date '+%b %e %H:%M:%S')
            lines=(
                "$ts demo sshd[$RANDOM]: Failed password for root from $ip port $((RANDOM + 1024)) ssh2"
                "$ts demo sshd[$RANDOM]: Invalid user admin from $ip port $((RANDOM + 1024))"
                "$ts demo sshd[$RANDOM]: Failed password for invalid user test from $ip port $((RANDOM + 1024)) ssh2"
                "$ts demo waf[$RANDOM]: Possible SQL injection from $ip: GET /login?id=1' OR 1=1 --"
                "$ts demo waf[$RANDOM]: XSS attempt from $ip: <script>alert(1)</script>"
                "$ts demo sshd[$RANDOM]: Accepted publickey for naseer from 192.0.2.200 port 51022 ssh2"
            )
            echo "${lines[RANDOM % ${#lines[@]}]}" >> "$LOG_FILE"
            (( RANDOM % 25 == 0 )) && echo "$ts demo sshd[$RANDOM]: Accepted password for root from $ip port 40022 ssh2" >> "$LOG_FILE"
            sleep $(( RANDOM % 3 + 1 ))
        done
    ) &
    DEMO_PID=$!

    echo -e "${PURPLE}DEMO MODE${RESET} - simulated attacks are written to $LOG_FILE (nothing is really blocked)"
}

# Set up state files and the log source
init() {
    load_config

    if (( DEMO_MODE )); then
        start_demo
    else
        if (( EUID != 0 )); then
            echo -e "${ERROR}Run as root (sudo) to read system logs and manage iptables, or use --demo.${RESET}"
            exit 1
        fi
        resolve_log_source
        ignore_own_addresses
    fi

    if ! mkdir -p "$STATE_DIR" || ! touch "${STATE_DIR}/ids.log" "${STATE_DIR}/blocked_ips.log"; then
        echo -e "${ERROR}Cannot write to $STATE_DIR${RESET}"
        exit 1
    fi
    log_event "IDS started (source: $LOG_FILE, demo: $DEMO_MODE)"
}

# Follow the log source and analyse each new line; reports run on a timer
monitor_logs() {
    echo -e "${GREEN}Bash IDS running${RESET} - source: $LOG_FILE | alert at $ALERT_THRESHOLD, block at $BLOCK_THRESHOLD events in ${TIME_WINDOW}s"
    echo "Press Ctrl+C to stop"
    echo "---------------------------------------"

    local last_report line
    last_report=$(date +%s)

    if [[ "$LOG_FILE" == "journal" ]]; then
        exec 3< <(journalctl -f -n 0 -o short)
    else
        exec 3< <(tail -F -n 0 "$LOG_FILE" 2>/dev/null)
    fi

    while true; do
        # Wait up to 5 seconds for a line, so reports still appear when the log is quiet
        if IFS= read -r -t 5 line <&3; then
            analyze_line "$line"
        elif (( $? <= 128 )); then
            break   # the log source closed
        fi

        if (( $(date +%s) - last_report >= REPORT_INTERVAL )); then
            generate_report
            last_report=$(date +%s)
        fi
    done
}

cleanup() {
    trap '' INT TERM PIPE
    # Stop background processes first, so nothing is left running even if output fails
    [[ -n "$DEMO_PID" ]] && kill "$DEMO_PID" 2>/dev/null
    pkill -P $$ 2>/dev/null
    log_event "IDS stopped"

    echo -e "\n${ORANGE}Stopping IDS...${RESET}"
    generate_report
    [[ -n "$DEMO_DIR" ]] && rm -rf "$DEMO_DIR"
    exit 0
}

list_blocked() {
    iptables -S INPUT | grep -- "--comment $RULE_TAG" | awk '{print $4}' | sed 's#/32##'
}

unblock_ip() {
    local ip=$1
    if iptables -D INPUT -s "$ip" -m comment --comment "$RULE_TAG" -j DROP 2>/dev/null; then
        echo "Unblocked $ip"
    else
        echo "$ip is not blocked by this IDS"
    fi
}

# Match patterns regardless of upper or lower case
shopt -s nocasematch

case "${1:-}" in
    --demo)          DEMO_MODE=1 ;;
    --list-blocked)  list_blocked; exit ;;
    --unblock)       [[ -n "${2:-}" ]] || { usage; exit 1; }; unblock_ip "$2"; exit ;;
    -h|--help)       usage; exit 0 ;;
    "")              ;;
    *)               echo "Unknown option: $1"; usage; exit 1 ;;
esac

trap cleanup INT TERM PIPE
init
monitor_logs
cleanup
