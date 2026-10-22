# ReconX 🔍

**ReconX** is a comprehensive automated reconnaissance and exploitation-assistance tool designed for penetration testers and security professionals. It streamlines the initial phases of a security assessment by automating host discovery, deep port scanning, service-specific enumeration, and vulnerability identification.

---

## 🚀 Features

* **Advanced Port Scanning:** Integrates with `nmap` to perform fast or full port sweeps, service detection, and script scanning (`-sV -sC`).
* **Service Enumeration:** Automatically targets open ports with specialized tools:
  * **Web (HTTP/HTTPS):** Header retrieval, title grabbing, SSL cert analysis, directory brute-forcing (`gobuster`), and web vuln scanning (`nikto`).
  * **SMB:** Share enumeration, user discovery, and vulnerability checks (including EternalBlue checks) via `enum4linux`, `crackmapexec`, and `netexec`.
  * **Active Directory / LDAP:** Domain context discovery and anonymous searches.
  * **Kerberos & DNS:** User enumeration (`kerbrute`) and zone transfer checks (`AXFR`).
* **Vulnerability Analysis:** Cross-references open ports and version banners against known exploits and suggests targeted commands (Metasploit modules, Impacket scripts, etc.).
* **Interactive Exploitation Mode:** Prompts the user to review suggested exploit commands and optionally execute them directly from the tool.
* **Structured Reporting:** Automatically exports all findings and raw scan outputs into JSON (`reconx_<IP>.json`) and Nmap formats.

---

## 🛠️ Prerequisites & Dependencies

Make sure you have Python 3 and the required security tools installed on your system (ideally on a penetration testing distribution like Kali Linux or Parrot OS):

* `nmap`
* `gobuster`
* `nikto`
* `enum4linux` / `crackmapexec` / `netexec`
* `kerbrute`

---

## ⚙️ Usage

Clone the repository and run the script with root privileges (required for certain nmap scan types):

```bash
git clone [https://github.com/YOUR_USERNAME/ReconX.git](https://github.com/YOUR_USERNAME/ReconX.git)
cd ReconX
sudo python3 ReconX.py <TARGET_IP> [--fast]
