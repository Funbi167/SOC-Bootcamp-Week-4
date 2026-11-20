# CCF SOC Accelerator – Week 4: Live Network Traffic Investigation (Telnet vs SSH)

**Programme:** CCF Bootcamp – SOC Accelerator | **Week:** 4 – Network Security Monitoring (NSM)
**Team:** Sentinel – *Remote access* | **Tools:** Wireshark 4.6.8, Ubuntu (WSL2), OpenSSH, `inetutils-telnetd`

> All testing was done on a machine I own, using a dummy account (`testuser`). No third-party traffic was captured.

## 1. Objective

Generate two kinds of remote-access traffic, capture them in Wireshark, and explain what a SOC analyst can (and cannot) see:

| Activity | Protocol | Port | Result in Wireshark |
|---|---|---|---|
| 1 | Telnet | TCP 23 | Username, password, commands and server output in **clear text** |
| 2 | SSH | TCP 22 | Version banners and algorithm negotiation visible; session is **encrypted** |

## 2. Lab setup

The test server is an Ubuntu 26.04 LTS instance running in WSL2 on my Windows 11 laptop (WSL IPv4 `192.168.122.184`). The client is the Windows Command Prompt. Both services run on the same machine, so traffic travels over the **loopback** interface.

**Server preparation (Ubuntu / WSL):**

```bash
sudo apt install telnetd              # pulls in inetutils-telnetd, openbsd-inetd, tcpd
sudo adduser testuser                 # dummy account for the exercise
sudo service ssh start                # start OpenSSH server
sudo sed -i 's/^#<off>#\s*telnet/telnet/' /etc/inetd.conf   # enable telnet entry in inetd
sudo service inetd restart
ss -tlnp | grep -E ':22|:23'          # confirm both ports are LISTENING
hostname -I                           # 192.168.122.184
```

Screenshots: [01](../screenshots/01-install-telnetd-and-create-testuser.png) · [02](../screenshots/02-start-ssh-and-inetd-check-ports.png) · [03](../screenshots/03-enable-telnet-in-inetd-ports-22-and-23-listening.png)

![Install telnetd and create testuser](../screenshots/01-install-telnetd-and-create-testuser.png)
![Start services and check ports](../screenshots/02-start-ssh-and-inetd-check-ports.png)
![Telnet enabled; 22 and 23 listening](../screenshots/03-enable-telnet-in-inetd-ports-22-and-23-listening.png)

**Troubleshooting notes (real issues I hit):**

- `inetutils-inetd.service` did not exist – the service on this Ubuntu release is simply `inetd`.
- The `telnet` line in `/etc/inetd.conf` was disabled (`#<off>#`); I removed the prefix with `sed`, restarted `inetd`, and `ss` then showed port 23 listening alongside 22.
- `dism /online /Enable-Feature /FeatureName:TelnetClient` is a Windows command – it failed inside Linux. The Windows Telnet client has to be enabled from Windows.
- Windows could not reach the WSL listener until I set the Hyper-V firewall default inbound action to **Allow** (screenshot 04). **This weakens the firewall – revert it after the lab** (`Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction NotConfigured`).

![Hyper-V firewall setting](../screenshots/04-hyperv-firewall-allow-inbound-to-wsl.png)

## 3. Capturing the traffic

Because client and server are on the same host, I captured on Wireshark's **Adapter for loopback traffic capture** (Npcap) using capture filters `tcp port 23` and `tcp port 22`. The frames use *Null/Loopback* encapsulation, so there are **no Ethernet MAC addresses** in these captures.

![Capture filter on loopback adapter](../screenshots/07-wireshark-loopback-adapter-capture-filter.png)
![Capture filter tcp port 22](../screenshots/09-wireshark-capture-filter-tcp-port-22.png)

| | Telnet capture | SSH capture |
|---|---|---|
| File | `pcaps/telnet.pcapng` (+ `telnet2.pcapng`, see note) | `pcaps/ssh.pcapng` |
| Client → Server | `::1` : 16011 → `::1` : **23** | `127.0.0.1` : 31706 → `127.0.0.1` : **22** |
| IP version | IPv6 (client resolved `localhost` to `::1`) | IPv4 |
| Packets | 237 | 2,019 |
| Duration | ≈ 37 s | ≈ 38 s |

> **Note:** I repeated the Telnet exercise and saved the second capture as `telnet2.pcapng`. The Follow TCP Stream screenshots (11, 12) and `pcaps/stream-exports/telnet2_tcp_stream.pdf` come from that run, which includes a failed login followed by a successful one. Stream exports of both protocols are in `pcaps/stream-exports/`.

## 4. Activity 1 – Telnet (TCP 23)

**How it was generated** (Windows CMD, as Administrator):

```
telnet localhost        # login: testuser, then whoami, pwd, ls, exit
```

![Telnet session](../screenshots/08-telnet-login-session-cmd.png)

**Wireshark filters used:** `telnet`, `tcp.port == 23`, then *Right-click → Follow → TCP Stream*.

**What happened in the packets**

1. **TCP three-way handshake** – frames 1–3: `SYN` → `SYN, ACK` → `ACK` (16011 → 23).
2. **Telnet option negotiation** – frames 4–25 and beyond: `Will/Do/Don't/Won't` for Authentication, Encryption, Terminal Type, Window Size, New Environment. The server offers authentication/encryption options and the client declines them (`Don't Authentication Option`, `Don't Encryption Option`) – so **no protection is negotiated**.
3. **Login and session** – the server sends the banner and `login:` prompt; the client sends the username, then the password **one keystroke per packet** (the 1-byte `TELNET` frames, each ACKed and echoed).
4. **Commands** – `whoami`, `pwd`, `ls`, `exit` travel as plain text, followed by the server's Ubuntu welcome banner.
5. **Teardown** – `FIN, ACK` from both sides (frames 234–237) closes the connection cleanly.

![Telnet handshake and negotiation](../screenshots/06-wireshark-telnet-handshake-and-option-negotiation.png)
![Telnet data and teardown](../screenshots/05-wireshark-telnet-pcap-packet-list-and-teardown.png)

**Recovered from the capture (client → server TCP payload, ignoring option bytes):**

```
testuser\r\n
<password typed at the prompt>\r\n        # dummy lab password, visible in clear text
whoami\r\npwd\r\nls\r\nexit\r\n
```

**Server → client payload (also readable):** hostname `DESKTOP-A67S0F4`, kernel `6.18.58.1-microsoft-standard-WSL2`, OS `Ubuntu 26.04.1 LTS`, internal IP `192.168.122.184`, memory/process stats, and the commands' output.

**Follow TCP Stream (`telnet2.pcapng`, stream 0, 4,785 bytes, 68 client / 74 server packets)**

![Telnet Follow TCP Stream – failed login then successful login](../screenshots/11-wireshark-telnet-follow-stream-failed-then-successful-login.png)

- The first login attempt used a mistyped password. The server replied **`Login incorrect`** and showed a new `login:` prompt – a **failed authentication is visible in clear text**.
- The second attempt succeeded and the Ubuntu welcome banner followed.
- Each typed character appears **twice** in the stream view (once from the client in red, once echoed back by the server in blue), which is why `testuser` looks like `ttestestuserr`. The password is not echoed by the server, but it still crosses the wire in the client's packets.
- The Ubuntu welcome banner leaks the **OS version, kernel, hostname and internal IP** (`192.168.122.184`).

![Telnet Follow TCP Stream – commands](../screenshots/12-wireshark-telnet-follow-stream-commands-in-cleartext.png)

- `whoami`, `pwd`, `ls` and `exit` are readable, along with the shell prompt (`testuser@DESKTOP-A67S0F4:~$`) and the `logout`.
- The long `]3008;...` strings are terminal escape sequences from the shell (Ubuntu's session-tracking metadata). They are noise for analysis, but they also expose the user, hostname, machine ID and working directory.

**Visible vs not visible**

| Visible | Not visible |
|---|---|
| Username, password, every command and its output | Anything about the user's real identity beyond what they type |
| Server OS/kernel/hostname/internal IP (banner) | MAC addresses (loopback capture) |
| Negotiated Telnet options (no encryption/authentication) | – |

## 5. Activity 2 – SSH (TCP 22)

**How it was generated:**

```
ssh testuser@localhost       # first attempt: host key prompt -> answered "no"
ssh testuser@127.0.0.1       # accepted host key (yes), entered password, ran whoami, pwd, ls, exit
```

![SSH session](../screenshots/10-ssh-login-session-cmd.png)

The first attempt showed the **unknown host key warning** (ED25519 fingerprint). Answering `no` aborted before any login; answering `yes` stored the key in `known_hosts`. This is SSH's trust-on-first-use model – a user (or analyst) should verify the fingerprint out-of-band.

**Wireshark filters used:** `ssh`, `tcp.port == 22`.

**Wireshark filters used:** `ssh`, `tcp.port == 22`, Follow TCP Stream.

**What is visible (from `pcaps/ssh.pcapng`, 2,019 packets)**

![SSH packet list](../screenshots/13-wireshark-ssh-packet-list-handshake-then-encrypted.png)

| Frame(s) | What happens |
|---|---|
| 1–3 | TCP three-way handshake, `31706 → 22` (a single connection: one SYN, one SYN-ACK) |
| 4 and 6 | **Protocol version banners**, in clear text: client `SSH-2.0-OpenSSH_for_Windows_9.5`, server `SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8` |
| 8 and 10 | **Key Exchange Init** from the client (1,476 bytes) and the server (1,084 bytes): each side lists its supported algorithms, unencrypted |
| 12 and 14 | **Elliptic Curve Diffie-Hellman Key Exchange Init / Reply**. The server's reply (frame 14) also carries *New Keys* and the first encrypted packet |
| 16 | Client **New Keys**, at ≈ 5.46 s. The ≈ 5 s gap since frame 14 matches the time I spent answering the host-key prompt |
| 18 onward | Only `Encrypted packet (len=…)`: password login, `whoami`, `pwd`, `ls`, `exit` |

**Key Exchange Init – the algorithm lists an analyst can read**

![Client Key Exchange Init](../screenshots/14-wireshark-ssh-client-key-exchange-init.png)
![Server Key Exchange Init](../screenshots/15-wireshark-ssh-server-key-exchange-init.png)

| Category | Client (OpenSSH for Windows 9.5) | Server (OpenSSH 10.2p1) |
|---|---|---|
| Key exchange | `curve25519-sha256`, `ecdh-sha2-nistp256/384/521`, `diffie-hellman-group*` | `mlkem768x25519-sha256`, `sntrup761x25519-sha512` (post-quantum hybrids), `curve25519-sha256`, `ecdh-sha2-nistp*` |
| Host key | `ssh-ed25519` (and certificate variants), `ecdsa-sha2-nistp*`, `rsa-sha2-*` | `rsa-sha2-512/256`, `ecdsa-sha2-nistp256`, `ssh-ed25519` |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes*-ctr`, `aes128/256-gcm@openssh.com` | `chacha20-poly1305@openssh.com`, `aes128/256-gcm@openssh.com`, `aes*-ctr` |
| MACs | `umac-*`, `hmac-sha2-256/512` (and `-etm` variants) | same, plus `hmac-sha1` variants |
| Extras | `ext-info-c`, `kex-strict-c-v00@openssh.com` | `ext-info-s`, `kex-strict-s-v00@openssh.com` |

**Likely negotiated algorithms** (derived from SSH's selection rule: the first algorithm in the client's list that the server also supports; confirm by expanding *SSH Protocol* in Wireshark):

- Key exchange: `curve25519-sha256` (the client does not offer the ML-KEM or sntrup hybrids)
- Host key: `ssh-ed25519` – this matches the `ED25519` fingerprint prompt shown in the SSH session screenshot
- Cipher: `chacha20-poly1305@openssh.com` (an authenticated cipher, so no separate MAC is needed)

**Follow TCP Stream on the SSH session (stream 0, 45 kB, 489 client / 517 server packets, 970 turns)**

![SSH Follow TCP Stream](../screenshots/16-wireshark-ssh-follow-stream-encrypted.png)

Only the two banner lines at the top of the stream are readable. Everything after them is binary noise. The same session in Telnet exposed the credentials and every command, and in SSH none of it can be recovered. The full export is in `pcaps/stream-exports/ssh_tcp_stream.pdf`.

**Visible vs not visible**

| Visible | Not visible |
|---|---|
| Source/destination IP and port, timing, packet sizes | Username, password |
| Client and server software + version (banners) | Commands and their output |
| Offered key-exchange, cipher, MAC and host-key algorithms | Session content, files transferred |
| Whether the session is long-lived and how much data moved (≈ 45 kB total) | Which commands were run or whether login succeeded (without logs) |

## 6. Telnet vs SSH at a glance

| | Telnet | SSH |
|---|---|---|
| Port | TCP 23 | TCP 22 |
| Encryption | None | Yes (after key exchange) |
| Credentials in capture | ✅ Readable | ❌ Encrypted |
| Server authentication | None | Host key (fingerprint check) |
| Integrity protection | None – sessions can be altered/hijacked | MAC / AEAD |
| Follow TCP Stream shows | Whole session | Binary garbage after key exchange |
| Verdict | Legacy, avoid | Preferred standard |

## 7. What this tells a SOC analyst

**Telnet – any occurrence is an alert-worthy finding**

- Alert on **any traffic to/from TCP 23**, especially crossing the network perimeter or from the internet (`tcp.port == 23` in Wireshark/IDS; firewall logs for dst port 23).
- Cleartext credential exposure: treat the account as **compromised** and force a password reset.
- A **`Login incorrect`** string in the stream is a failed-authentication event visible on the wire (the host's auth log will also record it). Repeated failures from one source suggest password guessing.
- Telnet option negotiation with `Don't Encryption/Authentication` confirms no protection was in place.
- Also check for the telnet daemon being started on endpoints (`inetd`, `telnetd`, new listener on :23 in `ss`/EDR) – attackers and legacy IoT devices use it.
- Remote shell commands from unexpected sources (`whoami`, `id`, `wget`, …) are visible and can be matched to threat-hunting rules.

**SSH – content is hidden, so look at metadata and behaviour**

- **Brute force:** many short TCP/22 connections from one source, repeated failed logins (`Failed password` in `/var/log/auth.log` or `journalctl -u ssh`).
- Successful login from a **new/unusual source, country or time** (`Accepted password for … from …`).
- **Long-lived sessions or large data volume** (possible tunnelling/exfiltration) – the PCAP shows size and timing even when content is hidden.
- SSH on **non-standard ports** or from hosts that should not use it.
- **Outdated client/server banners** (version strings are visible) – helps identify vulnerable software and fingerprint tools.
- **Host-key change warnings** – may indicate a man-in-the-middle or a rebuilt server.

## 8. Security implications & recommendations

1. **Disable Telnet everywhere**; remove `telnetd`/`inetd` entries (`sudo apt purge telnetd openbsd-inetd`) and block TCP 23 at host and perimeter firewalls.
2. **Use SSH** for remote administration; prefer **key-based authentication** and disable password login (`PasswordAuthentication no`), disable root login, and consider `fail2ban`/rate limiting.
3. **Restrict SSH exposure:** allow only from management networks/VPN, use `AllowUsers`, keep OpenSSH patched.
4. **Verify host-key fingerprints** on first connection and manage `known_hosts` centrally.
5. **Monitor & log:** forward auth logs and firewall logs to the SIEM; alert on port 23 activity, SSH brute force and anomalous SSH sessions.
6. **Segment and monitor network traffic** (IDS/NSM such as Zeek or Suricata) so legacy cleartext protocols are detected even if they are already in use.
7. **Lab hygiene:** I reverted/should revert the Hyper-V firewall `Allow` change and uninstall telnetd after the exercise.

## 9. Useful Wireshark filters

```
telnet                         tcp.port == 23
ssh                            tcp.port == 22
tcp.flags.syn == 1 && tcp.flags.ack == 0     # new connection attempts
tcp.flags.fin == 1                           # connection teardown
ssh.protocol                                 # version banners
ssh.message_code == 20                       # Key Exchange Init
```

## 10. Repository structure

```
ccf-soc-week4-telnet-vs-ssh/
├── pcaps/          telnet.pcapng, ssh.pcapng (add telnet2.pcapng here, see note in section 3)
│   └── stream-exports/   Follow TCP Stream exports (PDF) for Telnet and SSH
├── readme/         README.md  (this file)
└── screenshots/    01 … 16 lab and Wireshark screenshots
```

## 11. Key takeaways

- Telnet gives an analyst (and an attacker) **everything**: credentials, commands, output.
- SSH hides the content but still leaks **useful metadata** – IPs, ports, timing, volume and software versions.
- Following the same two sessions side by side makes the contrast obvious: readable text for Telnet, binary noise for SSH.
- Good monitoring means combining **packet captures with host/authentication logs**.
- Even a simple lab teaches troubleshooting: service names, firewall layers, and loopback capture details matter.

## Disclaimer

For educational use in a controlled lab. Only dummy credentials were used on systems I own. Do not capture or inspect traffic without permission.

#CCFBootcamp #CCFSOCAccelerator #SOC #Wireshark #NetworkSecurity
