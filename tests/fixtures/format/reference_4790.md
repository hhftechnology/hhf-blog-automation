system | 2026-11-07 14:30:53 UTC | #1

Here’s a roundup of **18 critical/high security issues** disclosed this week affecting popular open-source self-hosted projects, plus **2 earlier advisories** (see *Missed Earlier*). Start with your edge: Start with your edge: secure components like Traefik and Caddy that have high severity vulnerabilities, and then move on to patch identity management tools such as Keycloak.

---

### **1. LXD: Authentication bypass through unverified client certificate chains**

**GHSA-99jp-jwmc-65p4** / **CVE-2026-112816** | Disclosed: November 4, 2026

**Project** : LXD

**Technical Details** : LXD versions 4.0.14, 5.0.10, 5.21.8, and 6.9 contain an authentication bypass flaw where the HTTPS listener requests client certificates without verifying them. An attacker can exploit this issue to authenticate as any trusted certificate by appending that certificate's public part to their own chain, without holding the matching private key.

* **Severity** : Critical (CVSS 10.0)
* **Affected** : lxd 4.0.14, 5.0.10, 5.21.8, 6.9
* **Fixed** : 4.0.15, 5.0.11, 5.21.9, 6.10.0, 6.10.1
* **Workaround** : Restrict network access to the HTTPS listener to trusted hosts. There is no configuration based workaround.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| CVE-2026-112816 | 10.0 | Public PoC | 0.003 (23.2th percentile) | Patch within 72h |

**Remediation Steps**

1. Upgrade LXD to the fixed release for your branch (4.0.15, 5.0.11, 5.21.9, 6.10.0, 6.10.1), or a later version.
2. If you cannot upgrade immediately, apply the vendor workaround: Restrict network access to the HTTPS listener to trusted hosts. There is no configuration based workaround.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 4.0.15 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/canonical/lxd/security/advisories/GHSA-99jp-jwmc-65p4
- NVD CVE-2026-112816: https://nvd.nist.gov/vuln/detail/CVE-2026-112816

**Reference** : [GHSA-99jp-jwmc-65p4](https://github.com/canonical/lxd/security/advisories/GHSA-99jp-jwmc-65p4)

---

### **2. LXD has restricted project bypass leading to arbitrary command execution**

**GHSA-47w9-6r3f-938g** (no CVE yet) | Disclosed: November 6, 2026

**Project** : LXD

**Technical Details** : A vulnerability in github.com/canonical/lxd versions prior to 0.0.0-20260630083100-c5184be310b1 involves instance snapshots ignoring the restricted.containers.lowlevel=block setting. This flaw allows an attacker to bypass project restrictions and achieve arbitrary command execution on the Incus server with root privileges by abusing lowlevel hooks such as raw.lxc and raw.qemu. Users of the LXD project running affected versions are vulnerable to this issue.

* **Severity** : Critical (CVSS 9.9)
* **Affected** : github.com/canonical/lxd &lt; 0.0.0-20260630083100-c5184be310b1
* **Fixed** : 0.0.0-20260630083100-c5184be310b1
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| — (no CVE yet) | 9.9 | Public PoC | N/A | Patch within 72h |

**Remediation Steps**

1. Upgrade LXD to **0.0.0-20260630083100-c5184be310b1** or later, for example `go get github.com/canonical/lxd@v0.0.0-20260630083100-c5184be310b1` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 0.0.0-20260630083100-c5184be310b1 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/canonical/lxd/security/advisories/GHSA-47w9-6r3f-938g
- GHSA-47w9-6r3f-938g: https://github.com/advisories/GHSA-47w9-6r3f-938g

**Reference** : [GHSA-47w9-6r3f-938g](https://github.com/advisories/GHSA-47w9-6r3f-938g)

---

### **3. LXD has arbitrary file write on client due to trusted image hash**

**GHSA-pjff-c2wc-f6jm** (no CVE yet) | Disclosed: November 6, 2026

**Project** : LXD

**Technical Details** : An arbitrary file write flaw exists in the Incus client when a malicious image server returns a crafted Incus-Image-Hash header because the file is created and populated before its SHA-256 is validated. This vulnerability can lead to arbitrary command execution as root on the server. Users of github.com/canonical/lxd prior to version 0.0.0-20260630083100-c5184be310b1 are affected.

* **Severity** : Critical (CVSS 9.9)
* **Affected** : github.com/canonical/lxd &lt; 0.0.0-20260630083100-c5184be310b1
* **Fixed** : 0.0.0-20260630083100-c5184be310b1
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| — (no CVE yet) | 9.9 | Public PoC | N/A | Patch within 72h |

**Remediation Steps**

1. Upgrade LXD to **0.0.0-20260630083100-c5184be310b1** or later, for example `go get github.com/canonical/lxd@v0.0.0-20260630083100-c5184be310b1` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 0.0.0-20260630083100-c5184be310b1 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/canonical/lxd/security/advisories/GHSA-pjff-c2wc-f6jm
- GHSA-pjff-c2wc-f6jm: https://github.com/advisories/GHSA-pjff-c2wc-f6jm

**Reference** : [GHSA-pjff-c2wc-f6jm](https://github.com/advisories/GHSA-pjff-c2wc-f6jm)

---

### **4. Traefik: Per-connection backend transport leak from unauthenticated Negotiate/NTLM headers (3.7.14+)**

**GHSA-xv5x-242w-7hf7** (no CVE yet) | Disclosed: November 2, 2026

**Project** : Traefik

**Technical Details** : Traefik contains a high severity vulnerability in its NTLM and Kerberos backend connection handling affecting versions 2.11.58 through 2.11.60 and versions 3.7.14 through 3.7.16. Unauthenticated clients can exploit this flaw by opening many short-lived connections containing specific Authorization headers, causing Traefik to leak backend transports, idle connections, and goroutines that are not released when the client connection closes. This resource leak allows an attacker to exhaust the memory, file descriptors, and backend connections of the Traefik process regardless of whether NTLM or Kerberos backends are configured.

* **Severity** : High (CVSS 7.5)
* **Affected** : github.com/traefik/traefik/v2 &gt;= v2.11.58, &lt;= v2.11.60; github.com/traefik/traefik/v3 &gt;= v3.7.14, &lt;= v3.7.16
* **Fixed** : v2.11.61, v3.7.17
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| — (no CVE yet) | 7.5 | None known | N/A | Patch this week |

**Remediation Steps**

1. Upgrade Traefik to the fixed release for your branch (v2.11.61, v3.7.17), or a later version.
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is v2.11.61 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/traefik/traefik/security/advisories/GHSA-xv5x-242w-7hf7

**Reference** : [GHSA-xv5x-242w-7hf7](https://github.com/traefik/traefik/security/advisories/GHSA-xv5x-242w-7hf7)

---

### **5. Caddy: Host and :authority values with dot segments or slashes escape a {host}-based root**

**GHSA-r766-rf9f-588h** (no CVE yet) | Disclosed: November 4, 2026

**Project** : Caddy

**Technical Details** : Sites using a root path based on the request host allow clients to choose the document root because HTTP/2 and HTTP/3 servers insufficiently validate the `:authority` header, accepting characters like dot segments, slashes, and backslashes. An attacker can exploit this flaw to move the document root anywhere on the filesystem, allowing the fileserver to serve files and phpfastcgi to run PHP files outside the intended tree. This vulnerability affects Caddy versions up to 2.11.7.

* **Severity** : High
* **Affected** : github.com/caddyserver/caddy/v2 &lt;= 2.11.7
* **Fixed** : 2.11.8
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| — (no CVE yet) | N/A | Public PoC | N/A | Patch this week |

**Remediation Steps**

1. Upgrade Caddy to **2.11.8** or later, for example `docker pull caddy:2.11.8` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 2.11.8 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/caddyserver/caddy/security/advisories/GHSA-r766-rf9f-588h

**Reference** : [GHSA-r766-rf9f-588h](https://github.com/caddyserver/caddy/security/advisories/GHSA-r766-rf9f-588h)

---

### **6. Keycloak has authentication bypass via jwt algorithm confusion**

**GHSA-j97h-3f8r-mrjr** / **CVE-2026-11800** | Disclosed: November 3, 2026

**Project** : Keycloak

**Technical Details** : A JWT algorithm confusion vulnerability exists in the JWT Authorization Grant flow of Keycloak services prior to version 26.6.4. This flaw allows an attacker with valid client credentials to bypass signature verification and forge an assertion to create unauthorized access tokens. Consequently, affected users of Keycloak facing this issue can have attackers impersonate any federated user linked to the affected Identity Provider, leading to unauthorized access and potential privilege escalation.

* **Severity** : High (CVSS 8.1)
* **Affected** : org.keycloak:keycloak-services &lt; 26.6.4
* **Fixed** : 26.6.4
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| CVE-2026-11800 | 8.1 | None known | 0.003 (22.9th percentile) | Patch this week |

**Remediation Steps**

1. Upgrade Keycloak to **26.6.4** or later, for example `docker pull keycloak/keycloak:26.6.4` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 26.6.4 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/keycloak/keycloak/security/advisories/GHSA-j97h-3f8r-mrjr
- GHSA-j97h-3f8r-mrjr: https://github.com/advisories/GHSA-j97h-3f8r-mrjr
- NVD CVE-2026-11800: https://nvd.nist.gov/vuln/detail/CVE-2026-11800

**Reference** : [GHSA-j97h-3f8r-mrjr](https://github.com/advisories/GHSA-j97h-3f8r-mrjr)

---

### **7. Gitea: Stored XSS on the Gitea origin through the v3 artifact Content-Encoding header**

**GHSA-9v6p-xpcp-7488** / **CVE-2026-113429** | Disclosed: November 1, 2026

**Project** : Gitea

**Technical Details** : Gitea versions up to 28.2.0 are vulnerable to a stored cross-site scripting flaw because the v3 Actions artifact upload stores the Content-Encoding request header without validation and subsequently serves it as the Content-Type. An attacker who can run a single job is able to supply a crafted header value that causes Chromium to render arbitrary HTML on the Gitea origin. This issue affects users of the Gitea project whose instances run vulnerable versions up to 28.2.0.

* **Severity** : High (CVSS 8.7)
* **Affected** : gitea.dev &lt;= 28.2.0
* **Fixed** : 28.3.0
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| CVE-2026-113429 | 8.7 | None known | 0.002 (6.6th percentile) | Patch this week |

**Remediation Steps**

1. Upgrade Gitea to **28.3.0** or later, for example `docker pull gitea/gitea:28.3.0` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 28.3.0 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/go-gitea/gitea/security/advisories/GHSA-9v6p-xpcp-7488
- NVD CVE-2026-113429: https://nvd.nist.gov/vuln/detail/CVE-2026-113429

**Reference** : [GHSA-9v6p-xpcp-7488](https://github.com/go-gitea/gitea/security/advisories/GHSA-9v6p-xpcp-7488)

---

### **8. Gitea: Actions: fork workflow gets secrets and write token via review commit_id**

**GHSA-32h8-5xqg-h466** / **CVE-2026-118386** | Disclosed: November 1, 2026

**Project** : Gitea

**Technical Details** : Users with only read access to a repository can execute unauthorized workflows on the repository's Actions runner by submitting a specifically crafted pull request review. This flaw affects Gitea versions 1.19.0 up to 28.2.0. Consequently, the unapproved workflow runs with access to Actions secrets and a GITEATOKEN capable of committing to the repository.

* **Severity** : High (CVSS 8.1)
* **Affected** : gitea.dev &gt;= 1.19.0, &lt;= 28.2.0
* **Fixed** : 28.3.0
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| CVE-2026-118386 | 8.1 | None known | 0.001 (4.1th percentile) | Patch this week |

**Remediation Steps**

1. Upgrade Gitea to **28.3.0** or later, for example `docker pull gitea/gitea:28.3.0` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 28.3.0 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/go-gitea/gitea/security/advisories/GHSA-32h8-5xqg-h466
- NVD CVE-2026-118386: https://nvd.nist.gov/vuln/detail/CVE-2026-118386

**Reference** : [GHSA-32h8-5xqg-h466](https://github.com/go-gitea/gitea/security/advisories/GHSA-32h8-5xqg-h466)

---

### **9. Gitea: Write collaborators can replace and destroy releases, milestones and labels on archived repositories (archived write-protection bypass)**

**GHSA-6h2f-c8jm-84hc** / **CVE-2026-116296** | Disclosed: November 1, 2026

**Project** : Gitea

**Technical Details** : Gitea fails to enforce read-only semantics for archived repositories on the release, milestone, and label API route families. As a result, any authenticated user with ordinary write access to an archived repository can silently replace release binaries, permanently delete releases and their assets, and create, edit, or delete milestones and repository labels. This vulnerability affects self-hosted Gitea deployments up to version 28.2.0.

* **Severity** : High (CVSS 8.1)
* **Affected** : gitea.dev &lt;= 28.2.0
* **Fixed** : 28.3.0
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| CVE-2026-116296 | 8.1 | None known | 0.003 (18.6th percentile) | Patch this week |

**Remediation Steps**

1. Upgrade Gitea to **28.3.0** or later, for example `docker pull gitea/gitea:28.3.0` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 28.3.0 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/go-gitea/gitea/security/advisories/GHSA-6h2f-c8jm-84hc
- NVD CVE-2026-116296: https://nvd.nist.gov/vuln/detail/CVE-2026-116296

**Reference** : [GHSA-6h2f-c8jm-84hc](https://github.com/go-gitea/gitea/security/advisories/GHSA-6h2f-c8jm-84hc)

---

### **10. Mastodon: Password verification bypass when logging into inactive accounts**

**GHSA-3xjw-gv43-3w62** (no CVE yet) | Disclosed: November 3, 2026

**Project** : Mastodon

**Technical Details** : A flaw in the log-in logic of Mastodon allows a local user to switch to a different inactive local user mid-login, generating a sign-in token email without requiring the password. By brute-forcing the six-character base64 sign-in token, an attacker can bypass password authentication and complete the login as the targeted user. This vulnerability affects Mastodon versions 4.7.4 and versions ranging from 4.8.0-alpha.3 up to, but excluding, 5.0.0-alpha.3, specifically impacting inactive accounts without second-factor authentication where an attacker possesses a valid local user account.

* **Severity** : High
* **Affected** : Mastodon &gt;= 4.8.0-alpha.3, &lt; 5.0.0-alpha.3; Mastodon 4.7.4
* **Fixed** : 5.0.0-alpha.4, 4.7.5
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| — (no CVE yet) | N/A | None known | N/A | Patch this week |

**Remediation Steps**

1. Upgrade Mastodon to the fixed release for your branch (5.0.0-alpha.4, 4.7.5), or a later version.
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 5.0.0-alpha.4 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/mastodon/mastodon/security/advisories/GHSA-3xjw-gv43-3w62

**Reference** : [GHSA-3xjw-gv43-3w62](https://github.com/mastodon/mastodon/security/advisories/GHSA-3xjw-gv43-3w62)

---

### **11. Uptime Kuma: Authenticated RCE via Apprise CLI Argument Injection (Missing -- Separator)**

**GHSA-v2p3-6f5h-6hhf** (no CVE yet) | Disclosed: November 2, 2026

**Project** : Uptime Kuma

**Technical Details** : Uptime Kuma versions 1.0.6 through 2.5.7 are affected by an argument injection flaw in the Apprise notification provider, where user-controlled input is passed directly to a command without a separator. This allows authenticated attackers to inject arbitrary CLI flags, leading to authenticated server-side request forgery or, when combined with a file-write primitive, remote code execution.

* **Severity** : High
* **Affected** : uptime-kuma &gt;= 1.0.6, &lt;= 2.5.7
* **Fixed** : 2.5.8
* **Workaround** : None documented.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| — (no CVE yet) | N/A | Public PoC | N/A | Patch this week |

**Remediation Steps**

1. Upgrade Uptime Kuma to **2.5.8** or later, for example `docker pull louislam/uptime-kuma:2.5.8` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, limit exposure of the affected component (VPN-only access, reverse-proxy allow-list or firewall rule) until it is patched.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is 2.5.8 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/louislam/uptime-kuma/security/advisories/GHSA-v2p3-6f5h-6hhf

**Reference** : [GHSA-v2p3-6f5h-6hhf](https://github.com/louislam/uptime-kuma/security/advisories/GHSA-v2p3-6f5h-6hhf)

---

### Also disclosed this week

- LXD has argument injection in backup compression algorithm leading to AFW and ACE (GHSA-fmc8-p6q7-75cc; Critical (CVSS 9.9)) https://github.com/canonical/lxd/security/advisories/GHSA-fmc8-p6q7-75cc
- LXD has arbitrary file read+write on host via rootfs/ symlink in malicious image (GHSA-vghh-5rfx-xhq8; Critical (CVSS 9.9)) https://github.com/canonical/lxd/security/advisories/GHSA-vghh-5rfx-xhq8
- LXD has arbitrary file read+write on host via templates/ symlink in malicious image (GHSA-jpf8-86f3-wp38; Critical (CVSS 9.9)) https://github.com/canonical/lxd/security/advisories/GHSA-jpf8-86f3-wp38
- LXD has arbitrary file write on host via `exec-output` symlink in crafted image (GHSA-9j25-mm2h-2f76; Critical (CVSS 9.9)) https://github.com/canonical/lxd/security/advisories/GHSA-9j25-mm2h-2f76
- lxd allows Cross-guest volume hijack via DevLXD device patch (GHSA-hhf9-qw4v-72xp / CVE-2026-12411; High (CVSS 8.4)) https://github.com/canonical/lxd/security/advisories/GHSA-hhf9-qw4v-72xp
- LXD has project restriction bypass for custom volume copy across projects (GHSA-7mr3-28h5-m5vx; High (CVSS 7.7)) https://github.com/canonical/lxd/security/advisories/GHSA-7mr3-28h5-m5vx
- LXD has project restriction bypass in instance copy across projects (GHSA-qx75-2p3r-pwm5; High (CVSS 7.7)) https://github.com/canonical/lxd/security/advisories/GHSA-qx75-2p3r-pwm5

---

## Missed Earlier

These advisories were published 8 to 30 days ago and were not covered in an earlier summary.

### **12. Incus: Authentication and authorization bypass through unverified client certificate chains**

**GHSA-xg75-xf37-cph9** (no CVE yet) | Disclosed: October 29, 2026

**Project** : Incus

**Technical Details** : The HTTPS listener requests client certificates without verifying them, so the TLS handshake only proves that the client holds the private key of the first certificate in the chain it presents. The remaining certificates are entirely client controlled. The authentication and certificate ownership checks compared every certificate in the presented chain against the trust store.

* **Severity** : Critical (CVSS 10.0)
* **Affected** : github.com/lxc/incus/v7/cmd/incusd &lt; v7.6.0
* **Fixed** : v7.6.0
* **Workaround** : Restrict network access to the HTTPS listener to trusted hosts. There is no configuration based workaround.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| — (no CVE yet) | 10.0 | None known | N/A | Patch within 72h |

**Remediation Steps**

1. Upgrade Incus to **v7.6.0** or later, for example `go get github.com/lxc/incus/v7/cmd/incusd@v7.6.0` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, apply the vendor workaround: Restrict network access to the HTTPS listener to trusted hosts. There is no configuration based workaround.
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is v7.6.0 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/lxc/incus/security/advisories/GHSA-xg75-xf37-cph9

**Reference** : [GHSA-xg75-xf37-cph9](https://github.com/lxc/incus/security/advisories/GHSA-xg75-xf37-cph9)

---

### **13. Incus: Restricted project users can read or overwrite host files through special files, hard links or symlinks in backup or image metadata**

**GHSA-5pgx-q9xx-j3qv** (no CVE yet) | Disclosed: October 29, 2026

**Project** : Incus

**Technical Details** : A client with a restricted certificate that can create images, instances or backups in a project can import a backup or image whose metadata area — the instance volume excluding the guest rootfs, such as metadata.yaml, backup.yaml or any entry beside them — contains a special file, a hard link or a symlink in place of a regular file.

* **Severity** : Critical (CVSS 9.9)
* **Affected** : github.com/lxc/incus/v7/cmd/incusd &lt; v7.6.0
* **Fixed** : v7.6.0
* **Workaround** : Do not grant image, instance or backup creation to restricted certificates or restricted-project users for untrusted tenants until patched. Operators can audit imported instances for non-regular files, hard links or symlinks in the metadata area (everything in the instance volume except the rootfs…

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| — (no CVE yet) | 9.9 | None known | N/A | Patch within 72h |

**Remediation Steps**

1. Upgrade Incus to **v7.6.0** or later, for example `go get github.com/lxc/incus/v7/cmd/incusd@v7.6.0` (confirm the exact image or package tag in the vendor release notes).
2. If you cannot upgrade immediately, apply the vendor workaround: Do not grant image, instance or backup creation to restricted certificates or restricted-project users for untrusted tenants until patched. Operators can audit imported instances for non-regular files, hard links or symlinks in the metadata area (everything in the instance volume except the rootfs…
3. Review recent logs of the affected service for unusual requests before and after patching.
4. Verify: after the restart, confirm the running version is v7.6.0 or later and the service passes its health check.

**Official References**

- Vendor advisory: https://github.com/lxc/incus/security/advisories/GHSA-5pgx-q9xx-j3qv

**Reference** : [GHSA-5pgx-q9xx-j3qv](https://github.com/lxc/incus/security/advisories/GHSA-5pgx-q9xx-j3qv)

---

## Security-related releases

- **Caddy** [v2.11.9](https://github.com/caddyserver/caddy/releases/tag/v2.11.9) (2026-11-05)
- **Caddy** [v2.11.8](https://github.com/caddyserver/caddy/releases/tag/v2.11.8) (2026-11-04)
- **Pangolin** [1.26.0](https://github.com/fosrl/pangolin/releases/tag/1.26.0) (2026-11-04)
- **Keycloak** [26.8.2](https://github.com/keycloak/keycloak/releases/tag/26.8.2) (2026-11-05)
- **Vaultwarden** [1.37.5](https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.5) (2026-11-01)
- **Gitea** [v28.3.0](https://github.com/go-gitea/gitea/releases/tag/v28.3.0) (2026-11-01)
- **Uptime Kuma** [2.5.9](https://github.com/louislam/uptime-kuma/releases/tag/2.5.9) (2026-10-31)
- **Docker** [docker-v29.9.3](https://github.com/moby/moby/releases/tag/docker-v29.9.3) (2026-11-03)
- **Mastodon** [v4.7.5](https://github.com/mastodon/mastodon/releases/tag/v4.7.5) (2026-11-03)
- **Mastodon** [v4.6.11](https://github.com/mastodon/mastodon/releases/tag/v4.6.11) (2026-11-03)
- **Mastodon** [v4.5.21](https://github.com/mastodon/mastodon/releases/tag/v4.5.21) (2026-11-03)
- **Mastodon** [v4.4.28](https://github.com/mastodon/mastodon/releases/tag/v4.4.28) (2026-11-03)
- **AdGuard Home** [v0.107.80](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.80) (2026-11-03)
- **Open WebUI** [v0.13.0](https://github.com/open-webui/open-webui/releases/tag/v0.13.0) (2026-11-03)

---

## Sources

- GitHub Advisory Database (GHSA), CC-BY-4.0: https://github.com/advisories
- NVD CVE API 2.0. This product uses data from the NVD API but is not endorsed or certified by the NVD (https://nvd.nist.gov).
- OSV.dev: https://osv.dev (per-record licences apply)
- FIRST EPSS: See EPSS at https://www.first.org/epss
- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Ubuntu Security Notices: https://ubuntu.com/security/notices
- GitHub Releases of watchlist projects: https://docs.github.com/en/rest/releases

*Facts come from the sources above; the prose is AI-assisted from the supplied facts and fact-checked automatically. Always check the official advisory before acting.*

-------------------------

