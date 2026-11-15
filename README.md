# Bash IDS

A lightweight host-based intrusion detection script for Linux, written in Bash. It follows authentication logs in real time, scores each source IP inside a sliding time window, raises alerts and can block repeat offenders with iptables.

## Features

- Auto-detects the log source: `/var/log/auth.log`, `/var/log/secure` or the systemd journal
- Case-insensitive detection rules for brute force (failed passwords, invalid users) and web attacks (SQL injection, XSS)
- High-risk events (root logins, password changes, new users, sudo failures) are flagged immediately
- Sliding-window scoring: alert after 3 events and block after 5 events from the same IP within 10 minutes (configurable)
- Blocks with iptables, tagged so the tool only ever lists or removes its own rules
- Never blocks localhost or the machine's own addresses
- Periodic summary reports of top source IPs and recent blocks
- Optional email alerts
- Demo mode with realistic simulated attacks; needs no root and blocks nothing

## Requirements

- Linux with Bash 4+
- Root access for real monitoring (to read auth logs and manage iptables)
- `iptables` for blocking; `mail` for optional email alerts

## Usage

```bash
chmod +x ids.sh

./ids.sh --demo                 # try it safely with simulated attacks
sudo ./ids.sh                   # monitor the real logs
sudo ./ids.sh --list-blocked    # show IPs blocked by this tool
sudo ./ids.sh --unblock 1.2.3.4 # remove a block
```

To change settings, copy `project.conf.example` to `project.conf` and edit it. The config is only loaded if it is owned by root (or you) and not writable by other users, because the script runs as root.

## Example output (demo mode)

```
SUSPICIOUS: Failed password for root from 192.0.2.77 port 28937 ssh2 [192.0.2.77: 3 in window]
ALERT: 192.0.2.77 reached 3 events (block at 5)
SUSPICIOUS: XSS attempt from 198.51.100.23: <script>alert(1)</script> [198.51.100.23: 5 in window]
BLOCK (simulated): 198.51.100.23 - 5 events in 10 min
HIGH RISK: Accepted password for root from 192.0.2.77 port 40022 ssh2

==== SECURITY REPORT ====
Top source IPs:
  192.0.2.77        8 events
  198.51.100.23     6 events
Recently blocked:
  198.51.100.23
  192.0.2.77
```

Demo attacks use RFC 5737 documentation addresses, which can never belong to real hosts.

## How it works

1. Each new log line is checked against the high-risk rules, then the suspicious rules.
2. The first valid IPv4 address in the line is taken as the source.
3. The IP's event times are kept for the length of the time window; older events are dropped.
4. Reaching the alert threshold logs an alert (and emails it if configured); reaching the block threshold adds an iptables `DROP` rule at the top of the `INPUT` chain.

Logs are written to `/var/log/ids/ids.log` and `/var/log/ids/blocked_ips.log`.

## Limitations

- Pattern matching on log text is simple compared with tools like fail2ban, OSSEC/Wazuh or Suricata; attackers who do not trigger these log messages are not detected.
- IPv4 only.
- Blocks are permanent until removed with `--unblock` (or a reboot, since rules are not saved).
- Web-attack rules only work if a web server or WAF writes those messages to the monitored log.

This project was built for learning. Test it in a lab VM before using it on a real server.
