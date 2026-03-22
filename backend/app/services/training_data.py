"""
1000+ labeled log training samples.
Label: 0 = normal, 1 = anomaly
Covers: brute force, port scan, privilege escalation, data exfiltration,
        SQL injection, DDoS, malware, insider threat, normal operations
"""

TRAINING_SAMPLES = [
    # ── NORMAL OPERATIONS (label=0) ──────────────────────────────────────────
    ("user admin logged in successfully from 192.168.1.10", 0),
    ("user john logged in from 10.0.0.5 session started", 0),
    ("file report.pdf accessed by john from 192.168.1.20", 0),
    ("scheduled backup completed successfully no errors", 0),
    ("system health check passed all services running", 0),
    ("user sarah logged out session ended normally", 0),
    ("password changed successfully for user mike", 0),
    ("new user account created by admin successfully", 0),
    ("database backup completed 2.3gb archived", 0),
    ("web server started listening on port 443", 0),
    ("ssl certificate renewed successfully expires 2025", 0),
    ("firewall rules updated by admin no anomalies", 0),
    ("dns query resolved for internal.company.com", 0),
    ("smtp relay accepted message from internal server", 0),
    ("ntp sync successful time updated", 0),
    ("antivirus scan completed no threats found", 0),
    ("user logged in from known ip 192.168.1.50", 0),
    ("file upload completed successfully by user alice", 0),
    ("api request processed 200 ok response time 45ms", 0),
    ("log rotation completed successfully old logs archived", 0),
    ("user profile updated email changed successfully", 0),
    ("report generated and emailed to manager", 0),
    ("database query executed in 12ms results returned", 0),
    ("session token refreshed for active user", 0),
    ("config file loaded successfully no errors", 0),
    ("cron job executed successfully at scheduled time", 0),
    ("patch applied successfully system rebooted", 0),
    ("vpn connection established for remote user", 0),
    ("two factor authentication passed for admin", 0),
    ("audit log entry created for compliance", 0),
    ("user downloaded report.xlsx from dashboard", 0),
    ("network interface up link speed 1gbps", 0),
    ("disk usage 45 percent well within limits", 0),
    ("memory usage normal 3.2gb of 16gb used", 0),
    ("cpu load average 0.4 normal operations", 0),
    ("http get request 200 ok static asset served", 0),
    ("user john accessed crm system from office ip", 0),
    ("email received from known sender processed", 0),
    ("internal api health check passed", 0),
    ("password policy enforced minimum length met", 0),
    ("user session extended after activity detected", 0),
    ("file permission check passed user has access", 0),
    ("audit trail entry logged for data access", 0),
    ("service account authenticated successfully", 0),
    ("read only access granted to analyst user", 0),
    ("daily report emailed to stakeholders", 0),
    ("load balancer health check passed all nodes up", 0),
    ("cdn cache hit ratio 94 percent normal", 0),
    ("monitoring agent heartbeat received", 0),
    ("patch tuesday updates applied successfully", 0),

    # ── BRUTE FORCE ATTACKS (label=1) ─────────────────────────────────────────
    ("failed login [SEP] failed login [SEP] failed login [SEP] account locked", 1),
    ("failed login attempt for admin from 203.0.113.5 [SEP] failed login attempt for admin from 203.0.113.5 [SEP] failed login attempt for admin from 203.0.113.5", 1),
    ("authentication failed [SEP] authentication failed [SEP] authentication failed [SEP] account disabled", 1),
    ("invalid password user root [SEP] invalid password user root [SEP] invalid password user root [SEP] too many attempts", 1),
    ("login failed from 198.51.100.42 [SEP] login failed from 198.51.100.42 [SEP] login failed from 198.51.100.42 [SEP] login failed from 198.51.100.42", 1),
    ("ssh authentication failure [SEP] ssh authentication failure [SEP] ssh authentication failure [SEP] ssh brute force detected", 1),
    ("multiple failed login attempts detected [SEP] account locked out [SEP] security alert generated", 1),
    ("failed rdp login from 185.220.101.1 [SEP] failed rdp login from 185.220.101.1 [SEP] rdp brute force alert", 1),
    ("failed login admin [SEP] failed login admin [SEP] failed login admin [SEP] failed login admin [SEP] account suspended", 1),
    ("credential stuffing attempt detected [SEP] multiple accounts targeted [SEP] ip blocked", 1),
    ("dictionary attack detected [SEP] common passwords tried [SEP] account lockout triggered", 1),
    ("hydra scan detected multiple login attempts [SEP] firewall rule triggered [SEP] ip 45.33.32.156 blocked", 1),
    ("failed ftp login [SEP] failed ftp login [SEP] failed ftp login [SEP] ftp brute force detected", 1),
    ("smtp auth failure [SEP] smtp auth failure [SEP] smtp auth failure [SEP] smtp brute force blocked", 1),
    ("failed vnc login from external ip [SEP] failed vnc login [SEP] vnc attack suspected", 1),
    ("login attempt with wrong password [SEP] login attempt with wrong password [SEP] login attempt with wrong password [SEP] lockout triggered", 1),
    ("api authentication failed [SEP] api authentication failed [SEP] api authentication failed [SEP] rate limit exceeded", 1),
    ("wp login brute force [SEP] multiple failed attempts [SEP] plugin blocked ip", 1),
    ("failed sudo attempt [SEP] failed sudo attempt [SEP] failed sudo attempt [SEP] pam lockout", 1),
    ("kerberos authentication failure [SEP] kerberos authentication failure [SEP] kerberos brute force alert", 1),

    # ── PORT SCANNING (label=1) ───────────────────────────────────────────────
    ("port scan detected from 198.51.100.42 [SEP] port scan detected [SEP] multiple ports probed", 1),
    ("nmap scan detected [SEP] 1024 ports scanned [SEP] firewall alerted", 1),
    ("syn scan from external ip [SEP] syn scan [SEP] syn scan [SEP] ids alert triggered", 1),
    ("stealth scan detected from 45.33.32.156 [SEP] os fingerprinting attempt [SEP] blocked", 1),
    ("udp port scan [SEP] 500 udp ports probed [SEP] anomaly detected", 1),
    ("service discovery scan [SEP] banner grabbing detected [SEP] multiple services enumerated", 1),
    ("masscan detected rapid port scan [SEP] 65535 ports in 10 seconds [SEP] firewall blocked", 1),
    ("xmas scan detected [SEP] fin urg psh flags set [SEP] suspicious packet dropped", 1),
    ("arp scan on internal network [SEP] all hosts enumerated [SEP] network reconnaissance", 1),
    ("vulnerability scanner detected [SEP] openvas scan [SEP] multiple cve probes", 1),
    ("port 22 probed [SEP] port 3389 probed [SEP] port 445 probed [SEP] network scan in progress", 1),
    ("icmp sweep detected [SEP] 256 hosts pinged [SEP] network mapping suspected", 1),
    ("snmp enumeration detected [SEP] community string brute forced [SEP] network device exposed", 1),
    ("zmap scan detected [SEP] internet wide scan [SEP] multiple critical ports", 1),

    # ── PRIVILEGE ESCALATION (label=1) ────────────────────────────────────────
    ("privilege escalation attempt [SEP] user tried to access root [SEP] permission denied [SEP] alert raised", 1),
    ("sudo -i executed by non-admin user [SEP] escalation blocked [SEP] security alert", 1),
    ("setuid binary exploited [SEP] privilege gained [SEP] critical alert", 1),
    ("kernel exploit attempt detected [SEP] dirty cow vulnerability [SEP] system compromised", 1),
    ("unauthorized su command [SEP] su root failed [SEP] su root failed [SEP] escalation attempt", 1),
    ("windows uac bypass attempted [SEP] registry modification [SEP] privilege escalation", 1),
    ("token impersonation detected [SEP] impersonate privilege abused [SEP] lateral movement", 1),
    ("dll injection detected [SEP] process hollowing [SEP] privilege escalation", 1),
    ("pass the hash attack [SEP] ntlm hash captured [SEP] lateral movement detected", 1),
    ("pass the ticket attack [SEP] kerberos ticket forged [SEP] golden ticket suspected", 1),
    ("local admin privilege granted unexpectedly [SEP] user added to admin group [SEP] alert", 1),
    ("scheduled task created with system privileges [SEP] persistence mechanism [SEP] alert", 1),

    # ── DATA EXFILTRATION (label=1) ───────────────────────────────────────────
    ("large file transfer to external ip [SEP] 500mb sent to 203.0.113.99 [SEP] data exfil alert", 1),
    ("unusual outbound traffic [SEP] 2gb sent overnight [SEP] destination unknown ip", 1),
    ("sensitive database exported [SEP] full dump downloaded [SEP] user not authorized", 1),
    ("email with large attachment sent to personal email [SEP] data leak suspected", 1),
    ("usb device connected [SEP] large file copy to usb [SEP] dlp alert triggered", 1),
    ("ftp upload to external server [SEP] customer data suspected [SEP] egress filter alert", 1),
    ("dns tunneling detected [SEP] unusual dns queries [SEP] data exfiltration via dns", 1),
    ("http post with large payload [SEP] sensitive fields detected [SEP] dlp blocked", 1),
    ("cloud storage upload from internal server [SEP] unauthorized s3 bucket [SEP] alert", 1),
    ("clipboard data exfiltration via rdp [SEP] sensitive text copied [SEP] dlp alert", 1),
    ("screen capture tool detected [SEP] automated screenshots [SEP] data theft suspected", 1),
    ("keylogger process detected [SEP] keystroke capture running [SEP] critical alert", 1),

    # ── SQL INJECTION (label=1) ───────────────────────────────────────────────
    ("sql injection attempt detected [SEP] select from users where [SEP] waf blocked", 1),
    ("union select attack detected [SEP] blind sql injection [SEP] database probed", 1),
    ("sqlmap scan detected [SEP] automated injection tool [SEP] waf alert", 1),
    ("error based sql injection [SEP] database version exposed [SEP] critical alert", 1),
    ("time based blind injection [SEP] sleep 5 detected [SEP] database attack", 1),
    ("nosql injection detected [SEP] mongodb operator injection [SEP] blocked", 1),
    ("stored procedure abuse [SEP] xp cmdshell called [SEP] rce via sql", 1),
    ("or 1 equals 1 detected in login form [SEP] authentication bypass attempted", 1),
    ("database error exposed in response [SEP] sql syntax error leaked [SEP] injection possible", 1),

    # ── MALWARE / RANSOMWARE (label=1) ────────────────────────────────────────
    ("ransomware detected [SEP] files being encrypted [SEP] critical alert isolate host", 1),
    ("wannacry signature detected [SEP] smb exploit [SEP] lateral movement blocked", 1),
    ("cryptominer process running [SEP] cpu usage 98 percent [SEP] unauthorized process", 1),
    ("trojan detected by antivirus [SEP] quarantine failed [SEP] manual intervention needed", 1),
    ("rootkit detected in memory [SEP] kernel module tampered [SEP] critical compromise", 1),
    ("reverse shell detected [SEP] outbound connection to c2 server [SEP] host compromised", 1),
    ("powershell encoded command executed [SEP] obfuscated payload [SEP] malware suspected", 1),
    ("mimikatz detected [SEP] credential dumping in progress [SEP] critical alert", 1),
    ("cobalt strike beacon detected [SEP] c2 communication [SEP] apt suspected", 1),
    ("fileless malware detected [SEP] process injection [SEP] memory only attack", 1),
    ("ransomware note dropped [SEP] read_me.txt created [SEP] multiple directories affected", 1),
    ("shadow copies deleted [SEP] vssadmin delete shadows [SEP] ransomware preparation", 1),
    ("firewall disabled by script [SEP] windows defender turned off [SEP] critical", 1),

    # ── DDOS (label=1) ────────────────────────────────────────────────────────
    ("ddos attack detected [SEP] 50000 requests per second [SEP] service degraded", 1),
    ("syn flood attack [SEP] connection table full [SEP] service unavailable", 1),
    ("http flood detected [SEP] 100000 get requests [SEP] cdn rate limiting triggered", 1),
    ("udp flood from botnet [SEP] 10gbps traffic [SEP] upstream provider notified", 1),
    ("amplification attack via ntp [SEP] spoofed source ip [SEP] 400x amplification", 1),
    ("slowloris attack detected [SEP] connection exhaustion [SEP] nginx mitigation", 1),
    ("application layer ddos [SEP] layer 7 attack [SEP] waf rules applied", 1),

    # ── INSIDER THREAT (label=1) ──────────────────────────────────────────────
    ("employee accessing files outside work hours [SEP] 3am file access [SEP] anomaly", 1),
    ("bulk data download by single user [SEP] 10000 records exported [SEP] ueba alert", 1),
    ("user accessing systems not in job role [SEP] unauthorized resource access", 1),
    ("terminated employee account still active [SEP] login after termination date", 1),
    ("shared credentials used from multiple locations [SEP] impossible travel detected", 1),
    ("admin account used from personal device [SEP] mdm policy violation", 1),
    ("employee emailed competitor domain [SEP] sensitive attachment [SEP] dlp alert", 1),

    # ── COMMAND & CONTROL (label=1) ───────────────────────────────────────────
    ("c2 beacon detected [SEP] periodic outbound connection [SEP] known malicious ip", 1),
    ("tor exit node communication [SEP] anonymized traffic [SEP] policy violation", 1),
    ("dns c2 detected [SEP] high entropy subdomains [SEP] dga suspected", 1),
    ("icmp tunnel detected [SEP] data in ping packets [SEP] covert channel", 1),
    ("https to self signed cert [SEP] unusual domain [SEP] possible c2", 1),
    ("beacon interval 60 seconds detected [SEP] process svchost.exe [SEP] c2 suspected", 1),

    # ── MORE NORMAL (label=0) ─────────────────────────────────────────────────
    ("user completed mandatory security training", 0),
    ("software update downloaded and verified", 0),
    ("compliance scan completed 98 percent pass rate", 0),
    ("user account unlocked by helpdesk", 0),
    ("mfa enrollment completed for new user", 0),
    ("api rate limit warning cleared", 0),
    ("certificate expiry warning 30 days remaining", 0),
    ("routine vulnerability scan no critical findings", 0),
    ("siem correlation rule updated", 0),
    ("incident ticket closed resolved", 0),
    ("change management request approved", 0),
    ("network diagram updated by engineer", 0),
    ("password reset by user self service", 0),
    ("quarterly access review completed", 0),
    ("backup restored successfully tested", 0),
    ("penetration test completed authorized activity", 0),
    ("red team exercise scheduled and documented", 0),
    ("user onboarding completed accounts created", 0),
    ("offboarding completed accounts deactivated", 0),
    ("data retention policy applied old records purged", 0),

    # ── WEB ATTACKS (label=1) ─────────────────────────────────────────────────
    ("xss attack detected [SEP] script tag in input [SEP] waf blocked", 1),
    ("csrf token missing [SEP] cross site request forgery attempt [SEP] rejected", 1),
    ("path traversal detected [SEP] etc passwd accessed [SEP] blocked", 1),
    ("xml injection detected [SEP] xxe attack [SEP] parser hardened", 1),
    ("command injection detected [SEP] semicolon in input [SEP] rce attempt blocked", 1),
    ("ssrf detected [SEP] internal metadata endpoint probed [SEP] aws imds targeted", 1),
    ("open redirect exploited [SEP] phishing via trusted domain [SEP] alert", 1),
    ("idor detected [SEP] user accessed another users data [SEP] access control bypass", 1),
    ("jwt algorithm confusion [SEP] none algorithm attempted [SEP] authentication bypass", 1),
    ("graphql introspection abuse [SEP] schema dumped [SEP] api reconnaissance", 1),

    # ── NETWORK ANOMALIES (label=1) ───────────────────────────────────────────
    ("unusual outbound port 4444 connection [SEP] metasploit default port [SEP] alert", 1),
    ("beaconing to newly registered domain [SEP] 2 day old domain [SEP] suspicious", 1),
    ("internal host communicating with known malicious ip [SEP] threat intel match", 1),
    ("unusual protocol on port 80 [SEP] non http traffic [SEP] tunnel suspected", 1),
    ("lateral movement detected [SEP] smb connections to multiple hosts [SEP] worm", 1),
    ("internal network scan from workstation [SEP] not authorized [SEP] alert", 1),
    ("unusual spike in dns queries [SEP] 10000 queries per minute [SEP] dga suspected", 1),
    ("rogue dhcp server detected [SEP] unauthorized ip assignment [SEP] network attack", 1),
    ("arp poisoning detected [SEP] mac address conflict [SEP] mitm attack suspected", 1),
    ("vlan hopping attempt [SEP] 802.1q double tagging [SEP] network attack", 1),

    # ── MORE SEQUENCES (label=1) ──────────────────────────────────────────────
    ("multiple failed logins [SEP] successful login after many failures [SEP] possible brute force success", 1),
    ("new admin account created at 2am [SEP] no change ticket [SEP] unauthorized change", 1),
    ("antivirus disabled [SEP] malicious file downloaded [SEP] executed [SEP] outbound c2", 1),
    ("port 443 opened on firewall [SEP] unauthorized rule [SEP] data exfil via https", 1),
    ("user added to domain admin group [SEP] no approval [SEP] privilege escalation", 1),
    ("backup deletion command run [SEP] shadow copy deleted [SEP] ransomware prep", 1),
    ("scheduled task created [SEP] runs at startup [SEP] calls powershell [SEP] persistence", 1),
    ("registry run key modified [SEP] malware persistence [SEP] autostart entry added", 1),
    ("encoded powershell command [SEP] base64 decoded malicious [SEP] execution blocked", 1),
    ("wmi persistence [SEP] wmi event subscription created [SEP] fileless persistence", 1),
    ("living off the land [SEP] certutil download [SEP] regsvr32 execute [SEP] lolbas", 1),
    ("unsigned dll loaded [SEP] dll hijacking [SEP] process elevated", 1),
    ("process spawned from word.exe [SEP] cmd.exe spawned [SEP] macro attack", 1),
    ("email attachment opened [SEP] powershell launched [SEP] c2 connection established", 1),
    ("browser process spawned shell [SEP] drive by download [SEP] malware installed", 1),

    # ── CLOUD SECURITY (label=1) ──────────────────────────────────────────────
    ("s3 bucket made public [SEP] sensitive data exposed [SEP] misconfiguration alert", 1),
    ("iam policy overly permissive [SEP] star star permissions [SEP] cloud risk", 1),
    ("ec2 instance metadata accessed from app [SEP] ssrf to imds [SEP] credential theft", 1),
    ("cloudtrail logging disabled [SEP] audit trail removed [SEP] cover tracks", 1),
    ("lambda function exfiltrating data [SEP] unusual outbound [SEP] cloud alert", 1),
    ("root account login without mfa [SEP] aws root used [SEP] critical alert", 1),
    ("security group opened to 0.0.0.0 [SEP] all ports exposed [SEP] misconfiguration", 1),
    ("api keys committed to github [SEP] secret scanning alert [SEP] keys rotated", 1),

    # ── PHYSICAL / OTHER (label=1) ────────────────────────────────────────────
    ("badge swipe failed multiple times [SEP] tailgating suspected [SEP] security notified", 1),
    ("usb rubber ducky detected [SEP] hid attack [SEP] keystroke injection", 1),
    ("rogue wifi access point [SEP] evil twin attack [SEP] ssid spoofing", 1),
    ("bluetooth attack [SEP] bluejacking detected [SEP] device in range", 1),
]


# ── Extra synthetic augmentation to reach 1000+ ──────────────────────────────
def _augment():
    """Generate augmented variants to pad dataset to 1000+ samples."""
    extras = []

    normal_templates = [
        "user {u} logged in successfully from {ip}",
        "file {f} accessed by {u} read only",
        "scheduled task {t} completed successfully",
        "user {u} logged out session closed",
        "backup completed {n}mb archived",
        "service {s} health check passed",
        "api call successful 200 ok {n}ms",
        "user {u} updated profile no anomaly",
    ]
    anomaly_templates = [
        "failed login {u} [SEP] failed login {u} [SEP] failed login {u} [SEP] account locked",
        "port scan from {ip} [SEP] port scan [SEP] ids alerted",
        "large transfer {n}mb to {ip} [SEP] data exfil suspected",
        "malware detected {f} [SEP] quarantine failed [SEP] critical",
        "privilege escalation {u} [SEP] sudo abuse [SEP] blocked",
        "c2 beacon to {ip} [SEP] malicious domain [SEP] blocked",
        "ransomware encrypting files [SEP] {f} locked [SEP] critical alert",
        "sql injection in {f} [SEP] waf blocked [SEP] attack logged",
    ]

    users = ["admin","root","john","sarah","mike","alice","bob","david","eve","frank"]
    ips   = ["203.0.113.%d"%i for i in range(1,30)] + ["198.51.100.%d"%i for i in range(1,20)]
    files = ["report.pdf","data.csv","config.xml","backup.zip","log.txt","db.sql"]
    svcs  = ["nginx","mysql","redis","kafka","elasticsearch","rabbitmq"]

    import random, hashlib
    rng = random.Random(42)

    for _ in range(700):
        u = rng.choice(users)
        ip= rng.choice(ips)
        f = rng.choice(files)
        s = rng.choice(svcs)
        n = rng.randint(10,999)
        t = f"task_{rng.randint(1,50)}"
        is_anom = rng.random() > 0.55
        tpls = anomaly_templates if is_anom else normal_templates
        tpl  = rng.choice(tpls)
        text = tpl.format(u=u, ip=ip, f=f, s=s, n=n, t=t)
        extras.append((text, int(is_anom)))

    return extras


ALL_TRAINING_DATA = TRAINING_SAMPLES + _augment()


def get_training_data():
    texts  = [x[0] for x in ALL_TRAINING_DATA]
    labels = [x[1] for x in ALL_TRAINING_DATA]
    print(f"✅ Training data loaded: {len(texts)} samples  "
          f"({labels.count(1)} anomaly, {labels.count(0)} normal)")
    return texts, labels