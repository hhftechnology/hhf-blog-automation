### **1. Red Hat Keycloak: Keycloak JWT Algorithm Confusion Vulnerability**

**[CVE-2026-1111](https://nvd.nist.gov/vuln/detail/CVE-2026-1111)** | Disclosed: November 4, 2026
**[GHSA-aaaa-bbbb-cccc](https://github.com/keycloak/keycloak/security/advisories/GHSA-aaaa-bbbb-cccc)**
**Project** : Red Hat Keycloak

**New today**

**Technical Details** : Keycloak accepts tokens signed with an unexpected algorithm. CISA confirmed exploitation in the wild.

* **Severity** : Critical (CVSS 9.8)
* **Affected** : Affected versions are not listed in the available sources.
* **Fixed** : Check the vendor release notes.
* **Workaround** : None published. Upgrade when a fix is available.

| CVE | CVSS | Exploitation | EPSS | Action |
|---|---|---|---|---|
| [CVE-2026-1111](https://nvd.nist.gov/vuln/detail/CVE-2026-1111) | 9.8 | Confirmed exploited (CISA KEV) | 64.0% (99th percentile) | Patch now |

**Remediation Steps**

1. Patch or mitigate [CVE-2026-1111](https://nvd.nist.gov/vuln/detail/CVE-2026-1111) following the vendor guidance. CISA set a remediation due date of 2026-11-27.
2. Review exposed systems for signs of exploitation.
3. If remediation requires a restart, verify the fix and service health afterward.

**Official References**

- NVD [CVE-2026-1111](https://nvd.nist.gov/vuln/detail/CVE-2026-1111): https://nvd.nist.gov/vuln/detail/CVE-2026-1111
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Vendor advisory: https://github.com/keycloak/keycloak/security/advisories/GHSA-aaaa-bbbb-cccc
- CISA: https://news.example/vpn

**Reference** : [CVE-2026-1111](https://nvd.nist.gov/vuln/detail/CVE-2026-1111)
