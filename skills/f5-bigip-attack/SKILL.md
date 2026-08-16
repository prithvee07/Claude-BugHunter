---
name: f5-bigip-attack
description: F5 BIG-IP exploitation tradecraft — beyond fingerprinting (owned by enterprise-vpn-attack). Covers TMUI path-traversal pre-auth RCE (CVE-2020-5902), iControl REST authentication-bypass RCE (CVE-2022-1388), the Configuration-utility auth-bypass + SQLi chain (CVE-2023-46747 / CVE-2023-46748), BIGipServer persistence-cookie decoding to enumerate internal pool-member IPs (an SSRF-adjacent internal-network-mapping technique), iRules injection risk, and BIG-IQ centralized-management-plane exposure. Use once a target is confirmed as F5 BIG-IP (LTM/APM/ASM) via enterprise-vpn-attack's fingerprint step and you need the actual exploitation and internal-network-disclosure tradecraft, not just CVE identification.
sources: f5-security-advisories, cisa-kev, public-advisories, praetorian-research
report_count: 3
---

## Division of labor with `enterprise-vpn-attack`

`enterprise-vpn-attack` owns first-contact recon: banner fingerprinting (`BIGipServer*` cookies, `Server: BIG-IP`), the multi-vendor CVE matrix, and default-credential tables. Load this skill **after** that recon confirms F5 BIG-IP and you need to go from "vulnerable version" to shell, internal-network disclosure, or config exposure.

Trigger when: `enterprise-vpn-attack` has fingerprinted a `BIGipServer*` cookie or `TMUI`/`iControl REST` surface, or the target is a known BIG-IP build with an unpatched CVE from the matrix below.

---

## CVE-2020-5902 — TMUI path-traversal pre-auth RCE

**Affected:** BIG-IP 11.6.x, 12.1.x, 13.1.x, 14.1.x, 15.0.x/15.1.x Traffic Management User Interface (TMUI, the web config utility), prior to the July 2020 patch.

```bash
# Detection: classic TMUI traversal — reads an arbitrary file via the
# undocumented "locallb/workspace/fileRead.jsp" servlet reachable through
# a path-traversal past the login boundary.
curl -sk "https://$TARGET/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
# A response containing /etc/passwd content (root:x:0:0:...) confirms
# unauthenticated file read; the same primitive is used for file *write*
# to plant a webshell under the TMUI webroot for full RCE.
```

**Root cause:** The `;` character in the URL path was not correctly handled by the Apache-fronted TMUI, allowing `/tmui/login.jsp/..;/` to traverse out of the unauthenticated login context into internal administrative servlets that expect to run only post-auth.

**Real-world impact:** Disclosed and mass-exploited within days in July 2020 — CISA issued an emergency directive (ED 20-06) ordering federal agencies to patch or disconnect affected BIG-IP instances within 24 hours, an unusually aggressive timeline reserved for the highest-severity perimeter bugs. Public exploitation included webshell deployment, cryptomining, and reconnaissance of the internal network reachable from the BIG-IP's management interface. Because BIG-IP frequently sits at the network edge with routes into segments that ordinary DMZ hosts cannot reach, RCE here is a high-value internal-network foothold, not just an appliance compromise.

---

## CVE-2022-1388 — iControl REST authentication bypass → RCE

**Affected:** BIG-IP 16.1.x, 15.1.x, 14.1.x, 13.1.x prior to the May 2022 patch, when the iControl REST management interface (typically port 443 on the management IP, sometimes exposed on a self-IP) is reachable.

```bash
# Detection-only: confirm iControl REST is reachable and unauthenticated
# requests are rejected as expected (do not send the bypass payload
# without RCE-attempt sign-off — successful exploitation gives root).
curl -sk -o /dev/null -w "%{http_code}\n" "https://$TARGET/mgmt/tm/util/bash"
# 401 = endpoint present, normal auth enforcement — candidate for the
# bypass if the build is unpatched. 404 = endpoint not present/patched.
```

**Root cause:** A crafted HTTP request that manipulates the `Connection` header causes F5's internal reverse-proxy layer to forward a request to the iControl REST backend **without** the authentication check that the same request would receive through the normal request path — an internal-proxy trust-boundary bypass, conceptually similar to HTTP request smuggling but self-contained within F5's own component stack rather than a front-end/back-end mismatch. Once past authentication, `/mgmt/tm/util/bash` provides direct arbitrary command execution as root.

**Real-world impact:** Mass scanning and exploitation began within 48 hours of disclosure; CISA added this to KEV on the day of publication given confirmed active exploitation. This is one of the most consequential F5 CVEs on record because it requires no valid credentials at all and hands over root shell in a single request.

---

## CVE-2023-46747 + CVE-2023-46748 — Configuration-utility auth bypass chained with SQL injection → RCE

**Affected:** BIG-IP 13.1.x/14.1.x/15.1.x/16.1.x/17.1.x Configuration utility (the TMUI successor), prior to the October 2023 patch.

**Attack flow (two-CVE chain, publicly documented by Praetorian):**
1. CVE-2023-46747 — an authentication bypass in the Configuration utility, rooted in improper request handling similar in spirit to prior TMUI/AJP-boundary issues, grants an unauthenticated actor administrative access to the Configuration utility's authenticated-only endpoints.
2. CVE-2023-46748 — an authenticated SQL injection in a Configuration utility endpoint, now reachable unauthenticated via the chain above, allows execution of arbitrary system commands through the database layer.

**Operational note:** This pair illustrates a recurring BIG-IP pattern — the Configuration utility's front-end auth boundary and its backend request-processing have repeatedly diverged (TMUI in 2020, iControl REST in 2022, Configuration utility again in 2023), so treat *any* BIG-IP management-interface exposure as a standing high-risk surface regardless of which specific CVE is current, and re-check the F5 advisory index at engagement time for anything newer than what's listed in this skill.

---

## BIGipServer persistence-cookie decoding — internal network mapping / SSRF-adjacent recon

F5 BIG-IP LTM's cookie-based persistence (`BIGipServer<pool-name>=<value>`) encodes the **internal IP and port of the backend pool member** the session is pinned to — directly in the cookie, sent to every client, by design (F5 documents the format themselves for troubleshooting; this is not a vulnerability, it is an *information-disclosure-by-default* configuration that most deployments never bother to encrypt).

**Decoding (default, unencrypted persistence cookie):**

```python
# BIGipServer<pool>=<enc_ip>.<enc_port>.0000
# enc_ip: IPv4 octets stored in reverse (network) byte order, as a decimal
#         representation of the little-endian 32-bit integer.
# enc_port: port stored byte-swapped (network byte order), as decimal.

import struct

def decode_bigip_cookie(value):
    ip_enc, port_enc, _ = value.split(".")
    ip_int = int(ip_enc)
    ip = ".".join(str(b) for b in struct.pack("<I", ip_int))
    port = struct.unpack(">H", struct.pack("<H", int(port_enc)))[0]
    return ip, port

# Example: BIGipServerpool_internal_app=1677787402.36895.0000
print(decode_bigip_cookie("1677787402.36895.0000"))
```

**Why this matters:** Sending repeated requests and collecting distinct `BIGipServer*` values enumerates every backend pool member's **real internal IP address and port** — network topology that would otherwise require internal access to discover. This is routinely used to:
- Map internal application server ranges before/during authorized internal testing phases.
- Identify when a "load balanced" endpoint is actually backed by a single server (persistence cookie never changes) versus a real pool (multiple distinct decoded IPs across many requests).
- Spot internal IP ranges reused across environments (staging pool members sharing address space with production) — a config-hygiene finding worth reporting even without further exploitation.

**Mitigation F5 itself documents:** cookie encryption (`persist cookie encryption` in the profile) or HTTP-only + encrypted persistence. Its absence is a legitimate, reportable finding (internal topology disclosure) independent of any CVE — grade it Low/Informational unless it directly enables a further chain (e.g., combined with an SSRF elsewhere that can now target the disclosed internal IPs directly).

---

## iRules injection risk (methodology, not a single CVE)

**iRules** are F5's embedded Tcl-based traffic-scripting feature — administrators write custom logic (header rewriting, routing decisions, WAF-like filtering) that executes inline on every request. This is a **misconfiguration/custom-code class**, not a vendor CVE:

- If an iRule concatenates unsanitized request data (headers, URI, cookie values) into a `HTTP::redirect`, `HTTP::header replace`, or a backend selection expression, it can introduce open-redirect, header-injection, or pool-misrouting bugs specific to that organization's custom iRule — invisible to any vendor advisory because the vulnerable code is client-authored, not F5-shipped.
- Detection requires black-box behavioral testing (inject header-injection/traversal-style payloads into every header and observe routing/redirect behavior changes) since the iRule source is never visible externally — treat unusual, org-specific redirect or routing behavior on a confirmed BIG-IP target as a signal to probe here, and cross-reference with `hunt-open-redirect` / `hunt-html-injection` for the generic testing methodology once a candidate parameter is found.

---

## BIG-IQ (centralized management plane)

BIG-IQ centrally manages configuration, licensing, and often credentials for a fleet of BIG-IP devices — structurally analogous to how NetScaler Console/ADM relates to individual NetScaler appliances. Treat any recon hit on a BIG-IQ instance (distinct hostname/port, "BIG-IQ" branding on the login page) as **higher value than a single BIG-IP** — compromise cascades to every device it manages. Track F5's advisory index for BIG-IQ-specific CVEs separately at engagement time; this skill does not maintain a standing BIG-IQ CVE list because BIG-IQ deployments are far less common on the external perimeter than BIG-IP itself.

---

## Severity scoring guidance

| Finding | Severity |
|---|---|
| BIG-IP on internet, current patch, no mgmt-interface exposure | Informational |
| Unpatched CVE-2020-5902 / CVE-2022-1388 (unauth RCE-class) present | **Critical** — root shell, pivot to internal network |
| CVE-2023-46747/46748 chain present and reachable | **Critical** — same unauth-to-root outcome via a different path |
| BIGipServer cookie unencrypted, internal IPs enumerable | **Low/Informational** standalone; escalate if chained with an internal-IP-reachable SSRF elsewhere |
| iControl REST or Configuration utility reachable from the internet at all | **High** even pre-CVE — management interfaces should not be internet-facing; flag as a standing exposure issue regardless of current patch level |

---

## Anti-patterns

- **DO NOT fire the CVE-2022-1388 bypass payload without RCE-attempt sign-off** — successful exploitation is root-level command execution with no rollback.
- **DO NOT treat BIGipServer cookie decoding as "just" an SSRF technique** — it's passive, unauthenticated network-topology disclosure; it can be performed and reported even when no active exploitation is in scope.
- **DO NOT assume the Configuration utility and iControl REST share a patch state** — they are different services with different CVE histories on the same appliance.
- **DO NOT skip checking for a separate BIG-IQ asset** — organizations that patch individual BIG-IP devices diligently sometimes leave the centralized manager exposed and unpatched.

---

## Related Skills & Chains

- **`enterprise-vpn-attack`** — owns fingerprinting and the multi-vendor CVE matrix; load first to confirm BIG-IP + build before using this skill's exploitation detail.
- **`hunt-open-redirect`** / **`hunt-html-injection`** — custom iRules that mishandle request data reduce to these generic classes once a candidate injection point is found; this skill only covers the BIG-IP-specific *discovery* angle.
- **`hunt-ssrf`** — decoded internal pool-member IPs from BIGipServer cookies are high-value targets if any SSRF primitive elsewhere on the same organization's estate can be pointed at an internal address.
- **`cloud-iam-deep`** — BIG-IP instances fronting cloud-hosted backends sometimes hold cloud-provider credentials for autoscaling/health-check integration; a root shell via CVE-2020-5902/CVE-2022-1388 is a candidate source for those credentials.
- **`mid-engagement-ir-detection`** — F5 management-interface exploitation is a well-known IOC pattern; expect rapid detection and patching once RCE attempts are logged.

---

## Disclosed CVEs & citations

### 1. CVE-2020-5902 — TMUI remote code execution via path traversal
- **Affected:** BIG-IP 11.6.x, 12.1.x, 13.1.x, 14.1.x, 15.0.x/15.1.x TMUI, prior to the July 2020 patch (K52145254).
- **Disclosure:** F5 published advisory K52145254 2020-07-01. Reported by Mikhail Klyuchnikov of Positive Technologies. **CISA Emergency Directive 20-06** ordered federal agencies to patch or disconnect within 24 hours. Mass exploitation (webshells, cryptomining) followed within days of PoC publication.
- **References:** https://my.f5.com/manage/s/article/K52145254 ; https://www.cisa.gov/news-events/directives/ed-20-06-mitigate-f5-big-ip-vulnerability

### 2. CVE-2022-1388 — iControl REST authentication bypass
- **Affected:** BIG-IP 16.1.x, 15.1.x, 14.1.x, 13.1.x, prior to the May 2022 patch (K23605346).
- **Disclosure:** F5 published advisory K23605346 2022-05-04. **CISA KEV** added the same week following confirmed mass exploitation; multiple security vendors (Rapid7, Greynoise) documented internet-wide scanning within 48 hours of disclosure.
- **References:** https://my.f5.com/manage/s/article/K23605346 ; https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### 3. CVE-2023-46747 + CVE-2023-46748 — Configuration utility auth bypass chained with SQL injection
- **Affected:** BIG-IP Configuration utility across the 13.1.x-17.1.x train, prior to the October 2023 patch.
- **Disclosure:** Reported by researchers at Praetorian; F5 published advisories for both CVEs 2023-10-26. Public chain writeup by Praetorian documented the unauth-to-root path combining the two. **CISA KEV** added CVE-2023-46747 shortly after.
- **References:** https://my.f5.com/manage/s/article/K000137353 (verify current bulletin ID at exploitation time) ; https://www.praetorian.com/blog/refresh-compromising-f5-big-ip-with-request-smuggling-cve-2023-46747/

---

**Note on citation confidence:** As with every appliance-CVE skill in this bundle, verify the live F5 K-article number and current affected-build range at `my.f5.com/manage/s/` before citing a specific build in a client deliverable — F5 renumbers and consolidates advisories over time, and the identifiers above reflect the author's best recollection current to early 2026.
