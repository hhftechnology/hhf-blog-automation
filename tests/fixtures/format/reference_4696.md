Here’s a roundup of **11 critical/high security issues** disclosed this week affecting popular open-source self-hosted projects, plus **2 earlier advisories for imgproxy and Keycloak** we hadn’t covered yet (see *Missed Earlier*). Start with your edge: Traefik has an unauthenticated memory/FD exhaustion bug, Ubuntu’s BIND update fixes a possible GSS-TSIG RCE on 22.04, 24.04 and 26.04 LTS, and Caddy’s `{host}` root lets clients escape the site tree. Then patch fast: the WordPress core upgrade-window RCE is being exploited in the wild, Incus and LXD have a CVSS 10.0 authentication bypass, and pgAdmin’s Import/Export lets any database role run OS commands.

---

### **1. Traefik: Unauthenticated NTLM/Negotiate Header Exhausts Memory and FDs**

**GHSA-xv5x-242w-7hf7** (no CVE yet) | Disclosed: November 2, 2026  
**Project** : Traefik

**Technical Details** : Any request with an `Authorization: NTLM ...` or `Negotiate ...` header makes Traefik allocate a per-connection backend transport that is never released. Repeated requests exhaust memory and file descriptors, whether or not you have NTLM backends (FastProxy is affected too). It only affects recent patch releases, and v3.7.16 is still vulnerable, so check you’re on v3.7.17.

* **Severity** : High (CVSS 7.5)
* **Affected** : v2.11.58 – v2.11.60, v3.7.14 – v3.7.16
* **Fixed** : v2.11.61, v3.7.17
* **Workaround** : Strip `Authorization: NTLM` / `Negotiate` headers at an upstream proxy/WAF if you can’t upgrade immediately.

**Reference** : [GHSA-xv5x-242w-7hf7](https://github.com/traefik/traefik/security/advisories/GHSA-xv5x-242w-7hf7)

---

### **2. Ubuntu: BIND 9 GSS-TSIG Memory Corruption (Possible RCE) + 17 More DNS Fixes**

**CVE-2026-94300** (and 17 more, incl. CVE-2026-19630, CVE-2026-96888, CVE-2026-97313) | Disclosed: November 3, 2026 (USN-8969-1; ISC published the CVEs October 21)  
**Project** : Ubuntu (`bind9`)

**Technical Details** : USN-8969-1 updates BIND on Ubuntu 22.04, 24.04, 26.04 and 26.10. The worst bug, CVE-2026-94300, is in how `named` shares GSS-TSIG security contexts. An attacker who captures a previously signed UDP message can replay it while the negotiated TSIG key is still valid. Combined with crafted queries to a zone they control, that can corrupt memory and possibly run code. It matters if you use GSS-TSIG (Kerberos/Active Directory-style dynamic DNS). The same notice fixes resolver DoS bugs on the LTS releases: unlimited compression-pointer processing that burns CPU and memory (CVE-2026-19630, 7.5), a crash with `redirect` zones plus `qname-minimization strict` (CVE-2026-96888, 7.5), and an RPZ crash (CVE-2026-97313, 7.5). The other 14 CVEs, including TSIG zone-transfer injection, DNSSEC downgrade and out-of-zone cache poisoning, only affect Ubuntu 26.10.

* **Severity** : High (CVSS 8.1). Ubuntu rates it Medium priority
* **Affected** : `bind9` on Ubuntu 22.04 LTS, 24.04 LTS, 26.04 LTS and 26.10 (upstream BIND 9.11.0 – 9.18.50 and 9.20.0 – 9.20.29)
* **Fixed** : 22.04: `1:9.18.39-0ubuntu0.22.04.8`. 24.04: `1:9.18.39-0ubuntu0.24.04.9`. 26.04: `1:9.20.24-1ubuntu0.5`. 26.10: `1:9.20.24-1ubuntu3.1`. Run `sudo apt update && sudo apt upgrade` and restart `named`.
* **Workaround** : None in the notice. Until you patch, don't expose recursive resolvers to the internet, and limit GSS-TSIG updates to trusted hosts.

**Reference** : [USN-8969-1](https://ubuntu.com/security/notices/USN-8969-1) / [Ubuntu CVE-2026-94300](https://ubuntu.com/security/CVE-2026-94300) / [Ubuntu CVE-2026-19630](https://ubuntu.com/security/CVE-2026-19630)

---

### **3. Caddy 2.11.8: `{host}` in `root` Lets Clients Escape the Site Tree**

**GHSA-r766-rf9f-588h** (no CVE yet) | Disclosed: November 4, 2026  
**Project** : Caddy

**Technical Details** : If you build the site root from the Host header (e.g. `root /srv/sites/{host}`), the client picks the directory. HTTP/1.1 accepts `Host: ..`, and HTTP/2/3 accept `/` and `\` in `:authority`. So `file_server` serves files from outside the tree, and `php_fastcgi` runs them. The same release fixes Medium issues: a `php_fastcgi` path-rule bypass via dot segments (`/admin.php/../../nope.php`, CVSS 5.9, since 2.4.6), `file_server` exposing TLS private keys when the data dir falls back to `./caddy` (no `HOME`/`XDG_DATA_HOME` set), and two more path-matcher bypasses.

* **Severity** : High (no CVSS score yet)
* **Affected** : ≤ 2.11.7
* **Fixed** : 2.11.8
* **Workaround** : Don’t use `{host}` in `root`. Map hostnames to directories explicitly. Set `XDG_DATA_HOME` for the Caddy service user.

**Reference** : [GHSA-r766-rf9f-588h](https://github.com/caddyserver/caddy/security/advisories/GHSA-r766-rf9f-588h) / [GHSA-f278-mgc7-46j3](https://github.com/caddyserver/caddy/security/advisories/GHSA-f278-mgc7-46j3) / [GHSA-jf74-f69g-hcj9](https://github.com/caddyserver/caddy/security/advisories/GHSA-jf74-f69g-hcj9)

---

### **4. WordPress Core: Unauthenticated RCE During Core Upgrades (Actively Exploited)**

**CVE-2026-119977** | Disclosed: October 28, 2026 (WordPress 7.1.4 security release; added to CISA KEV November 3)  
**Project** : WordPress

**Technical Details** : When WordPress installs a full core package it unpacks the new files into a predictable folder under `wp-content/upgrade/`. That staged copy includes the installer (`wp-admin/setup-config.php`), and on many servers the folder is web-reachable and runs PHP. An unauthenticated attacker who requests the staged installer during the few seconds the update runs can get PHP code execution as the web server user. Wordfence saw the first attack requests nine minutes after its rule went live and more than 18,500 requests for staged `setup-config.php` paths in the first 21 hours, with some sources polling the same sites for ~14.5 hours to catch an update. 7.1.4 randomizes the staging folder name, keeps an `index.php` guard, and stops staged config from being promoted. The release fixes 22 issues in total.

* **Severity** : High (CVSS 8.1), on CISA KEV
* **Affected** : 4.7.0 – 7.1.3 (every branch)
* **Fixed** : 7.1.4, 7.0.8, 6.9.11, 6.8.12, 6.7.11 and backports down to 4.7.39. Sites on 4.6 or earlier get no fix.
* **Workaround** : Block HTTP access to `/wp-content/upgrade/` at the web server or CDN (nothing legitimate needs it). The update that *installs* 7.1.4 still runs the old upgrader, so grep access logs for `200` responses to `setup-config.php` / `install.php` under `wp-content/upgrade/` around your update time, and check `wp-config.php` for a database host you don’t recognize.

**Reference** : [Wordfence: WordPress 7.1.4 Security Release](https://www.wordfence.com/blog/2026/10/wordpress-7-1-4-security-release-rce/) / [CISA KEV alert (Nov 3)](https://www.cisa.gov/news-events/alerts/2026/11/03/cisa-adds-one-known-exploited-vulnerability-catalog)

---

### **5. Incus & LXD: Client Certificate Chain Authentication Bypass (CVSS 10.0)**

**CVE-2026-112816** (LXD) / **GHSA-xg75-xf37-cph9** (Incus, no CVE yet) | Disclosed: October 29, 2026 (Incus); November 4, 2026 (LXD advisory)  
**Project** : Incus / Canonical LXD

**Technical Details** : The HTTPS API listener asks for a client certificate but never verifies it. The trust check then compares *every* certificate in the presented chain against the trust store, so an attacker can append the public part of any trusted certificate and be authenticated as that client. Server certificates are returned in every TLS handshake, so a cluster member’s identity is easy to get. That gives full API access (and with it root on the host), plus the ability to renew or delete trust entries and to impersonate VM agent connections. The bug goes back to the initial release. Incus published 18 advisories the same day, including several more CVSS 9.9 host-root escapes: OCI image config / `oci.*` newline injection into the LXC config (root hooks on the host), restricted-project users creating instances in the default project, host file read/write through special files in backup/image metadata, and migration path traversal.

* **Severity** : Critical (CVSS 10.0)
* **Affected** : Incus before 7.6.0. LXD up to 4.0.14, 5.0.10, 5.21.8 and 6.9
* **Fixed** : Incus 7.6.0 (October 30). LXD 4.0.15, 5.0.11, 5.21.9 and 6.10.x. *Unverified:* I couldn’t find a fixed Incus 7.0.x LTS release yet (latest seen is 7.0.2 from October 16). Check your distro/Zabbly packages.
* **Workaround** : No config workaround. Restrict network access to the HTTPS listener (`core.https_address`) to trusted hosts until you’re patched, or unset it if you only use the local socket.

**Reference** : [Incus GHSA-xg75-xf37-cph9](https://github.com/lxc/incus/security/advisories/GHSA-xg75-xf37-cph9) / [LXD GHSA-99jp-jwmc-65p4](https://github.com/canonical/lxd/security/advisories/GHSA-99jp-jwmc-65p4) / [All Incus advisories](https://github.com/lxc/incus/security/advisories)

---

### **6. pgAdmin 4: Import/Export Lets Any DB Role Run OS Commands, Plus 14 More CVEs**

**CVE-2026-116241** (and CVE-2026-116238 – CVE-2026-116252) | Disclosed: October 30, 2026  
**Project** : pgAdmin 4

**Technical Details** : pgAdmin wraps Import/Export in a `\copy` command. A backslash-escaped double quote (with `standard_conforming_strings` off) breaks out of that wrapper and turns it into `COPY ... TO PROGRAM`, which runs as the pgAdmin OS user. Any ordinary database role can do it, and non-admin pgAdmin users get Import/Export permission by default. This is a bypass of the earlier CVE-2026-17566 fix. In the same batch: CVE-2026-116238 (CVSS v4 9.2) allows unlimited unauthenticated password guessing in server mode because the `/login`, `/verify`, `/change` and `/reset` views and case-insensitive email lookup skip the `MAX_LOGIN_ATTEMPTS` lockout; CVE-2026-116239 (CVSS v4 8.9) logs an LDAP/Kerberos user into a same-named internal account; and there are fixes for binary-path validation (CVE-2026-116243), SSH tunnel host key checking (CVE-2026-116242) and sessions not invalidated on password change (CVE-2026-116251).

* **Severity** : Critical (CVSS 3.1 9.9 / v4 9.4)
* **Affected** : pgAdmin 4 before 9.19
* **Fixed** : 9.19 (tagged November 4. Make sure your package or `dpage/pgadmin4` image is actually on 9.19)
* **Workaround** : Remove Import/Export permission from non-admin users, and don’t expose server-mode pgAdmin to the internet.

**Reference** : [NVD CVE-2026-116241](https://nvd.nist.gov/vuln/detail/CVE-2026-116241) / [NVD CVE-2026-116238](https://nvd.nist.gov/vuln/detail/CVE-2026-116238) / [pgAdmin issue #10663](https://github.com/pgadmin-org/pgadmin4/issues/10663)

---

### **7. Langflow: Auth Bypass + Unauthenticated Code Injection (8 CVEs)**

**CVE-2026-93680, CVE-2026-110186** (and CVE-2026-104339, -107327, -107328, -107329, -110193, -110192) | Disclosed: October 29, 2026 (IBM bulletin October 28, updated October 29)  
**Project** : Langflow

**Technical Details** : CVE-2026-93680 is an authentication bypass caused by an incomplete fix for the auto-login control. CVE-2026-110186 is unauthenticated code injection, which IBM’s bulletin describes as unauthenticated RCE via MCP tool enumeration. CVE-2026-104339 (OS command injection, ≤ 1.12.3) and CVE-2026-107327/107328/107329 (authenticated RCE, CVSS 9.9, ≤ 1.12.4) add more ways in, and CVE-2026-110193 (8.8) is in the Agentic Assistant. Langflow runs code by design, so any auth gap means a shell.

* **Severity** : Critical (CVSS 9.8 – 9.9)
* **Affected** : 1.0.0 – 1.12.8
* **Fixed** : 1.13.0 (`pip install --upgrade "langflow==1.13.0"` or `langflowai/langflow:1.13.0`). 1.13.1 and 1.12.9 followed on November 4. I haven’t checked what they change.
* **Workaround** : None. Back up the database and secret key before upgrading. If you rely on auto-login, set up password sign-in first. Don’t expose Langflow without an auth proxy in front.

**Reference** : [IBM Security Bulletin 7294467](https://www.ibm.com/support/pages/node/7294467) / [IBM 7293015](https://www.ibm.com/support/pages/node/7293015) / [IBM 7293016](https://www.ibm.com/support/pages/node/7293016)

---

### **8. ClickHouse: Unauthenticated Remote Code Execution**

**CVE-2026-116366** | Disclosed: October 30, 2026  
**Project** : ClickHouse Server

**Technical Details** : ClickHouse says only that “under certain conditions” an unauthenticated user with network access can execute arbitrary code on the server. No technical details or conditions have been published. ClickHouse Cloud and BYOC are already patched; self-hosted servers need an upgrade.

* **Severity** : Critical (CVSS v4.0 9.5)
* **Affected** : Open-source builds before the fixed versions below. ClickHouse hasn’t published an exact range.
* **Fixed** : v26.3.62.3-lts, v26.8.36.3-lts, v26.9.27.3-stable, v26.10.3.7-stable
* **Workaround** : None published. Until you upgrade, keep the HTTP (8123) and native (9000) ports off the internet and limit them to app hosts.

**Reference** : [ClickHouse Security Changelog](https://clickhouse.com/docs/resources/changelogs/security-changelog) / [NVD CVE-2026-116366](https://nvd.nist.gov/vuln/detail/CVE-2026-116366)

---

### **9. Gitea 28.3.0: OAuth2 Account Takeover, Actions Approval Bypass, 18 More**

**CVE-2026-120263, CVE-2026-118386, CVE-2026-113429, CVE-2026-117635** | Disclosed: November 1, 2026  
**Project** : Gitea

**Technical Details** : 20 advisories, 7 of them High. **CVE-2026-120263**: with `ACCOUNT_LINKING = auto` (not the default), anyone with an account on a configured OAuth2 provider can submit `/user/link_account_signup` with the victim’s `user_name`. Gitea auto-links by that attacker-controlled name, which gives a persistent takeover of any account, admins included. **CVE-2026-118386 (8.1)**: a read-only user can submit a PR review with the `commit_id` of their own commit, which runs Actions workflows without approval, with secrets and a write `GITEA_TOKEN`. **CVE-2026-113429 (8.7)**: stored XSS via a v3 artifact `Content-Encoding` (`video/mp4,text/html`) that drops the CSP sandbox. **CVE-2026-117635 (8.1)**: public-only tokens are accepted on the admin API and can create a site admin.

* **Severity** : High (CVSS up to 8.7. CVE-2026-120263 has no score yet)
* **Affected** : ≤ 28.2.0 (CVE-2026-118386 back to 1.19.0)
* **Fixed** : 28.3.0
* **Workaround** : Set `ACCOUNT_LINKING` to `disabled` or `login` until you upgrade, and require approval for all fork/PR workflows.

**Reference** : [GHSA-8p3x-w464-4g6v](https://github.com/go-gitea/gitea/security/advisories/GHSA-8p3x-w464-4g6v) / [GHSA-32h8-5xqg-h466](https://github.com/go-gitea/gitea/security/advisories/GHSA-32h8-5xqg-h466) / [All Gitea advisories](https://github.com/go-gitea/gitea/security/advisories)

---

### **10. Uptime Kuma: Apprise Argument Injection → RCE**

**GHSA-v2p3-6f5h-6hhf** (no CVE yet) | Disclosed: November 2, 2026  
**Project** : Uptime Kuma

**Technical Details** : The Apprise notification provider passes the user-supplied Apprise URL to `spawn("apprise", ...)` without a `--` separator. An authenticated user can inject `--plugin-path` (a Python import, which becomes RCE when combined with a file-write primitive) or `--config=URL` (SSRF). A separate Medium (GHSA-86ch-2247-gr56, CVSS 4.3) lets unauthenticated clients poison the status page RSS cache via the Host header.

* **Severity** : High (CVSS v4.0 8.7)
* **Affected** : 1.0.6 – 2.5.7
* **Fixed** : 2.5.8 (latest is 2.5.9, October 31)
* **Workaround** : None besides limiting who has Uptime Kuma accounts. Every logged-in user can create notification providers.

**Reference** : [GHSA-v2p3-6f5h-6hhf](https://github.com/louislam/uptime-kuma/security/advisories/GHSA-v2p3-6f5h-6hhf)

---

### **11. OPNsense: Firmware Mirror Setting → Root Command Injection**

**CVE-2026-119409** | Disclosed: October 30, 2026  
**Project** : OPNsense

**Technical Details** : A user with the *System: Firmware* privilege can store a firmware mirror URL with shell metacharacters via `POST /api/core/firmware/set`. `opnsense-update` evaluates it with `eval`, which runs commands as root, and a sed injection can also turn off package signature verification. Delegated admins who were only meant to manage updates get full root on the firewall.

* **Severity** : High (CVSS v4.0 8.6 / v3.1 7.2)
* **Affected** : Before 26.7.8
* **Fixed** : 26.7.8
* **Workaround** : Only full admins should hold the *System: Firmware* privilege. Keep the web GUI off WAN.

**Reference** : [OPNsense GHSA-p683-f7x2-pm4p](https://github.com/opnsense/core/security/advisories/GHSA-p683-f7x2-pm4p) / [NVD CVE-2026-119409](https://nvd.nist.gov/vuln/detail/CVE-2026-119409)

---

## **Key Takeaways This Week**

* **Exploited first**: WordPress CVE-2026-119977 is on CISA’s KEV list, and attackers are polling sites to catch the upgrade window. CISA also added GitLab’s CI/CD regex RCE (CVE-2026-97229, covered October 8–14, fixed in 19.4.2+) to KEV on October 29. If any GitLab box is still behind, do it today.
* **Your management plane is the target**: Incus/LXD, pgAdmin, OPNsense and ClickHouse all had bugs that end in root or OS-level code execution from the admin/API port. None of these APIs belong on the internet. Put them behind a VPN or allow-list.
* **“Read-only” and “restricted” users aren’t**: Gitea read-only users can run workflows with secrets, Incus restricted-project users can reach host root, and pgAdmin’s default non-admin role can run OS commands. Audit who has accounts.
* **Patch the OS too**: Besides BIND, Ubuntu’s November 3 batch includes kernel updates (USN-8959-1 for 26.04/24.04 HWE, USN-8961-1 for 22.04/20.04) and HAProxy DoS fixes (USN-8972-1). Kernel updates need a reboot.
* **Templated paths are dangerous**: Caddy’s `{host}` root and WordPress’s predictable staging folder are both path problems. Don’t build filesystem paths from request data.
* **AI/automation tooling keeps leaking**: Langflow (8 CVEs) this week, plus Flowise CVE-2026-119978 (CVSS v4 9.0, authenticated vm2 sandbox escape when `ALLOW_BUILTIN_DEP=true`, through 3.1.4) and n8n CVE-2026-119557 (Databricks node path traversal reachable from webhook/form input, 2.14.0 – 2.46.3).
* **Also this week**: Frappe CVE-2026-119145 (CVSS 9.9 authenticated upload path traversal → RCE, fixed 15.121.0 / 16.34.0). Docker Desktop for Windows (WSL2) CVE-2026-112917, a container escape to host services (fixed only with Docker Desktop 4.98.0 **and** WSL 3.0.3). vsftpd CVE-2026-119568: FTPS data channel accepts any resumed TLS ticket, so a client sharing the victim’s source IP (NAT) can steal or inject a transfer. No fixed vsftpd release yet (3.0.5 is latest). Setting `require_cert=YES` with client certs closes it.
* **Unpatched**: Jellyfin CVE-2026-119551 / CVE-2026-119549 (CVSS 7.1: `/Items/Suggestions` without `userId` bypasses library/parental restrictions; gzip-compressed SVG in a data-URI profile image gives SSRF/local image read) are listed as affecting “through 12.4” with no fixed release identified. Keep Jellyfin behind auth/VPN.

**Recommendation** : Review your self-hosted stack this weekend and prioritize upgrades for any of the above projects you’re running.

Stay secure!

*Questions or need config help? Post in [Help](https://forum.hhf.technology/c/help/85).*

---

## **Missed Earlier**

These came out before this week and weren’t in an earlier summary. They only reached the GitHub global advisory database this week.

### **12. imgproxy: ICO Loader Integer Overflow → Heap Overflow**

**GHSA-hff9-5pqw-6w9f** (no CVE) | Disclosed: October 6, 2026 (added to GitHub Advisory Database October 30)  
**Project** : imgproxy

**Technical Details** : In the ICO loader, `data_size + BMP_FILE_HEADER_LEN` can wrap around, which leads to a heap buffer overflow when processing a crafted `.ico`. Anyone who can make imgproxy fetch an image (the normal use case) can crash it or possibly execute code. Two related ICO issues (GHSA-494m-4556-wf5p and GHSA-mmq5-xm89-9pfg, both CVSS 7.5) were fixed in the same line.

* **Severity** : Critical (CVSS 9.8)
* **Affected** : 4.0.0 – 4.0.15
* **Fixed** : 4.0.16 (latest is 4.0.21, November 2)
* **Workaround** : Enable URL signing and restrict allowed source domains so arbitrary images can’t be fed in.

**Reference** : [GHSA-hff9-5pqw-6w9f](https://github.com/imgproxy/imgproxy/security/advisories/GHSA-hff9-5pqw-6w9f)

---

### **13. Keycloak: JWT Algorithm Confusion + Policy Enforcer Bypass**

**CVE-2026-11800, CVE-2026-9800** | Disclosed: June 26, 2026 (GitHub global advisories published October 29 / November 3)  
**Project** : Keycloak

**Technical Details** : **CVE-2026-11800**: JWT algorithm confusion in the JWT Authorization Grant flow lets an attacker with valid client credentials forge an assertion and impersonate any federated user linked to the affected Identity Provider. **CVE-2026-9800**: the Policy Enforcer can be bypassed by putting the configured access-denied page path in the request URL (path segment or query), which skips role, scope and UMA checks.

* **Severity** : High (CVSS 8.1 each)
* **Affected** : Keycloak server before 26.6.4. `keycloak-policy-enforcer` before 26.0.10
* **Fixed** : 26.6.4 and later (current is 26.8.1). `keycloak-policy-enforcer` 26.0.10
* **Workaround** : None. Upgrade. If you embed the policy enforcer in your own apps, bump that library too.

**Reference** : [GHSA-j97h-3f8r-mrjr](https://github.com/keycloak/keycloak/security/advisories/GHSA-j97h-3f8r-mrjr) / [GHSA-f5p5-6xmx-p252](https://github.com/keycloak/keycloak/security/advisories/GHSA-f5p5-6xmx-p252)