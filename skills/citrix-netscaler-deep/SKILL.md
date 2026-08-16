---
name: citrix-netscaler-deep
description: Deep Citrix NetScaler ADC/Gateway exploitation tradecraft — beyond fingerprinting (owned by enterprise-vpn-attack). Covers CitrixBleed (CVE-2023-4966) session-token theft and post-theft session hijack/2FA-skip, CitrixBleed 2 (CVE-2025-5777) memory-overread pattern, Shitrix (CVE-2019-19781) pre-auth directory-traversal RCE, CVE-2023-3519 pre-auth buffer-overflow RCE, CVE-2022-27518 (APT5-exploited) auth-bypass RCE, nFactor authentication flow abuse and factor-skip misconfigurations, AAA vserver LDAP/RADIUS bind-credential exposure, ns.conf/ns.log disclosure paths, and NetScaler Console/ADM management-plane attacks. Use once a target is confirmed as Citrix NetScaler ADC/Gateway (via enterprise-vpn-attack's fingerprint step) and you need the actual exploitation and post-token tradecraft, not just CVE identification.
sources: citrix-security-bulletins, cisa-kev, public-advisories, mandiant-research, ncc-group-research
report_count: 5
---

## Division of labor with `enterprise-vpn-attack`

`enterprise-vpn-attack` owns first-contact recon: banner fingerprinting, the multi-vendor CVE matrix (Cisco/Fortinet/Citrix/Palo Alto/Pulse/SonicWall/F5), and default-credential tables. Load this skill **after** that recon confirms NetScaler ADC/Gateway and you need to go from "vulnerable version" to "session token / shell / AAA credentials." Do not re-derive fingerprinting steps here — jump straight to exploitation and post-exploitation tradecraft.

Trigger when: `enterprise-vpn-attack` has fingerprinted `Set-Cookie: NSC_AAA=` / `NSC_USER=` / `Server: NetScaler`, or the target is a known NetScaler ADC/Gateway build with an unpatched CVE from the matrix below.

---

## CitrixBleed (CVE-2023-4966) — session token theft and hijack

**Affected:** NetScaler ADC and Gateway 13.0/13.1/14.1 configured as a Gateway (VPN virtual server, ICA proxy, CVPN, RDP proxy) or AAA virtual server, prior to the October 2023 patch builds.

**Root cause:** A buffer over-read in the HTTP request-processing path leaks adjacent heap memory into the HTTP response. When the request targets an endpoint that returns session-related data, the leaked bytes frequently contain **valid, already-authenticated NetScaler AAA session tokens** — including sessions belonging to other users, with no interaction from the victim required.

```bash
# Detection-only probe: does the response leak beyond the expected body?
# DO NOT harvest live session tokens without explicit sign-off — a leaked
# token is equivalent to full session hijack of a real user, including any
# admin sessions active at exploitation time.
curl -sk "https://$TARGET/oauth/idp/.well-known/openid-configuration" \
  -H "Host: $(python3 -c 'print("A"*24000)')" -o /tmp/citrixbleed_probe.bin
wc -c /tmp/citrixbleed_probe.bin
# A response body larger than the expected openid-configuration JSON, or one
# containing hex-looking session-ID-shaped strings, indicates the overread
# is firing on this build.
```

**Post-theft (only with explicit authorization for session-hijack testing):**
- A leaked NetScaler AAA session (`NSC_AAA` cookie value) can be replayed directly against the Gateway — **it bypasses MFA/2FA entirely**, because the token represents an *already-completed* authentication ceremony. This is the single most damaging property of CitrixBleed: it is not just an info leak, it is a full second-factor bypass.
- Confirm hijack by replaying the harvested cookie against `/gwtest/formssso` or the internal-resource path the session was scoped to, and checking for an internal-resource response rather than a re-auth redirect.
- Sessions persist until manually revoked — mass session invalidation (killing all active AAA/ICA sessions cluster-wide) is the only reliable remediation, which is why this CVE stayed exploited for months after patch: defenders patched the code path but did not always kill existing stolen sessions.

**Real-world impact:** CISA/FBI and multiple national CERTs documented mass exploitation from late 2023 into 2024, including large-scale ransomware access-broker activity (LockBit-affiliated actors were widely reported using CitrixBleed for initial access) and a disclosed breach at Boeing attributed to this CVE. Added to CISA KEV 2023-11-21.

---

## CitrixBleed 2 (CVE-2025-5777) — same class, second occurrence

**Affected:** NetScaler ADC/Gateway builds prior to the mid-2025 patch wave, when configured as a Gateway or AAA virtual server (same deployment prerequisite as the original CitrixBleed).

**Root cause:** A second, structurally similar out-of-bounds memory read in the same authentication/session-processing code path, disclosed roughly 18 months after CVE-2023-4966 was patched — the underlying memory-safety pattern in the authentication handler was not fully eradicated by the first fix. Public research (watchTowr Labs and others) confirmed unauthenticated memory disclosure capable of yielding session tokens, mirroring the original CitrixBleed exploitation chain.

**Operational note:** Treat any NetScaler build history that includes a gap between the 2023 CitrixBleed patch and the 2025 patch as a candidate — organizations that patched the first CVE and considered NetScaler "handled" are the highest-probability targets for the second. Detection and post-token tradecraft mirror CVE-2023-4966 above (memory-overread → session token → replay bypassing MFA). Confirm current patch level via the build-string probe in `enterprise-vpn-attack` before assuming exposure.

---

## Shitrix (CVE-2019-19781) — pre-auth directory traversal → RCE

**Affected:** NetScaler ADC/Gateway 10.5, 11.1, 12.0, 12.1, 13.0 prior to the January 2020 patch wave.

```bash
# Detection: directory traversal into the NetScaler's own config/template path
curl -sk "https://$TARGET/vpn/../vpns/cfg/smb.conf"
# A 200 with file contents = vulnerable and likely already patched-around by
# defenders (this CVE is 6 years old at the time of writing); a 403/404
# after this age most likely means patched or a WAF rule specifically
# targeting this signature.
```

**Attack flow:** Directory traversal from the `/vpn/` web root reaches the NetScaler's Perl-based template-rendering engine. Writing a crafted `.xml` template into the traversed path and then requesting it causes the NetScaler to render attacker-controlled Perl/NSPPE syntax, yielding command execution as `nobody`.

**Why it still matters in 2026:** This CVE triggered CISA's first-ever emergency directive for a non-federal-agency-specific vendor bug, was mass-exploited by both opportunistic ransomware crews and nation-state actors (public reporting links exploitation activity to APT41 and to REvil/Sodinokibi ransomware deployment) within days of PoC release, and — because NetScaler appliances are frequently "set and forget" perimeter infrastructure — unpatched instances are still found on external recon in 2026. Any hit here on a live engagement is an instant Critical.

---

## CVE-2023-3519 — pre-auth buffer overflow RCE

**Affected:** NetScaler ADC/Gateway 13.0/13.1 configured as a Gateway, AAA virtual server, or with specific load-balancing configurations, prior to the July 2023 patch.

**Root cause:** Unauthenticated stack buffer overflow reachable via the management/Gateway HTTP interface. CISA and NSA published a joint cybersecurity advisory (AA23-201A) documenting active exploitation of this CVE against a U.S. critical-infrastructure organization, including webshell implantation and Active Directory reconnaissance from the compromised appliance — a textbook illustration of NetScaler-as-initial-access into an internal network.

**Operational note:** Public exploit code for this CVE exists; do not run RCE-attempt payloads without explicit sign-off (a stack-overflow-class exploit can crash the appliance, taking down VPN access for the entire org). Detection-only: version/build fingerprint via `enterprise-vpn-attack`'s probe and cross-reference against the July 2023 patch builds is sufficient to flag Critical without live-firing the overflow.

---

## CVE-2022-27518 — auth-bypass RCE (APT5-exploited)

**Affected:** NetScaler ADC/Gateway configured as a SAML SP or IdP, specific 12.1/13.0 builds prior to the December 2022 patch.

**Root cause:** Unauthenticated remote code execution reachable when the appliance is configured for SAML authentication. The NSA published an advisory specifically naming **APT5 (also tracked as "Manganese" / UNC2630)**, a China-nexus threat actor, as actively exploiting this vulnerability to gain access to U.S. Department of Defense networks — an unusually direct public nation-state attribution for an appliance CVE.

**Chain relevance:** SAML-configured NetScaler Gateway overlaps directly with `hunt-saml`. If the target's NetScaler is federated (acting as SP against an external IdP, or as IdP itself), confirm the SAML role before assuming this CVE applies — it is scoped to the SAML code path specifically, not general Gateway auth.

---

## nFactor authentication flow abuse

NetScaler's **nFactor** feature chains multiple authentication policies (LDAP → RADIUS/OTP → certificate, etc.) into a configurable flow defined by administrators via policy labels. This is a **misconfiguration class**, not a single CVE — treat it as methodology:

- **Factor-skip via direct endpoint access.** If any intermediate factor in the nFactor chain is reachable as a standalone AAA vserver login form (rather than only through the chained flow), an attacker can sometimes authenticate against the weakest single factor (commonly plain LDAP) and receive a valid session without ever satisfying the OTP/certificate factor the chain was designed to enforce.
- **Policy-label misrouting.** nFactor flows are built from `add authentication loginSchema` / `add authentication policylabel` chains; a misordered or missing `gotoPriorityExpression` can let specific username patterns (or the absence of a expected header/client attribute) skip a factor entirely. This is enumerable only with config access (post-compromise) or by testing every reachable AAA vserver endpoint independently pre-auth.
- **Detection approach:** Enumerate every `/logon/LogonPoint/` and AAA vserver path found during recon, not just the primary Gateway URL — nFactor deployments frequently expose multiple entry points (one per factor stage) that were meant to be internal-only steps in the chain.

---

## AAA vserver LDAP/RADIUS bind-credential exposure

The NetScaler AAA (`add authentication ldapAction` / `add authentication radiusAction`) configuration stores the **service bind account** used to query the corporate directory — not end-user credentials, but a privileged service account with directory-read (and sometimes write) rights.

- `ns.conf` disclosure (via any of the RCE/traversal CVEs above, or via an exposed backup/support-bundle download endpoint) contains the LDAP bind DN and, in older builds, a reversible-encoded bind password (`-ldapBindDnPassword` stored with NetScaler's own symmetric encoding, not a one-way hash) — decode with the appliance's own `nsconmsg`/`nsbase64` utilities if you have local/shell access post-RCE, or with public NetScaler-config-decoder tooling.
- Treat a recovered LDAP bind credential as a **fresh initial-access credential for the internal AD**, not merely a NetScaler artifact — hand off to the client's internal-AD testing process (this bundle's external-only boundary applies once you have domain credentials in hand; using them for AD enumeration is out of scope here).

---

## NetScaler Console / ADM (management plane)

NetScaler Console (formerly ADM — Application Delivery Management) is a **separate product** from the ADC/Gateway data plane, typically reachable at a different hostname (`adm.target.com`, `nsconsole.target.com`) or a distinct port. Treat any recon hit on this product as a **higher-value target than the Gateway itself** — ADM holds centralized configuration and credentials for every NetScaler instance it manages, meaning compromise cascades to the entire appliance fleet, not one box.

- Fingerprint via login-page branding ("NetScaler Console", "Citrix ADM") and `/analyticsconfig`, `/nitro/v1/config` API paths.
- Treat ADM as its own patch-tracking target — do not assume ADM shares a patch cadence with the ADC/Gateway CVEs above; check Citrix's own security bulletin index for ADM-specific advisories at exploitation time rather than assuming coverage from this skill.

---

## Severity scoring guidance

| Finding | Severity |
|---|---|
| NetScaler on internet, current patch, no default creds | Informational |
| Unpatched CVE-2019-19781 / CVE-2023-3519 (RCE-class) present | **Critical** — full appliance compromise, pivot to internal network |
| Unpatched CVE-2023-4966 / CVE-2025-5777 (CitrixBleed family) | **Critical** — session hijack bypasses MFA entirely, not just info disclosure |
| nFactor factor-skip confirmed against a live login | **Critical** if it reaches an internal resource without the intended second factor |
| ns.conf / support-bundle disclosure without full RCE | **High** — credential exposure even without code execution |
| NetScaler Console/ADM reachable + auth weakness | **Critical** — blast radius is the entire managed fleet |

---

## Anti-patterns

- **DO NOT harvest and store real users' CitrixBleed-leaked session tokens** beyond the minimum needed to demonstrate hijack to the client — these are live credentials for real accounts.
- **DO NOT fire CVE-2023-3519's overflow payload without explicit RCE-attempt sign-off** — it can crash the appliance and take down production VPN access.
- **DO NOT assume CitrixBleed 2 patched status from the CitrixBleed 1 patch date** — they are different fixes 18 months apart; check the specific build.
- **DO NOT skip checking for NetScaler Console/ADM as a separate asset** — teams that patch the Gateway diligently sometimes forget the management plane runs on its own schedule.

---

## Related Skills & Chains

- **`enterprise-vpn-attack`** — owns fingerprinting and the multi-vendor CVE matrix; load first to confirm NetScaler + build before using this skill's exploitation detail.
- **`hunt-saml`** — CVE-2022-27518 and general NetScaler SAML SP/IdP configurations overlap directly; a federated NetScaler Gateway is both an appliance-CVE target and a SAML attack surface.
- **`hunt-rce`** — Shitrix and CVE-2023-3519 are both pre-auth RCE primitives; once shell is achieved, `hunt-rce`'s post-RCE guidance (credential harvesting, pivot documentation) applies.
- **`cloud-iam-deep`** — if the compromised NetScaler holds cloud-provider credentials (common in hybrid deployments where the appliance authenticates to a cloud LB/WAF control plane), the post-compromise credential-escalation guidance there applies.
- **`mid-engagement-ir-detection`** — NetScaler is heavily monitored in mature SOCs post-CitrixBleed; expect rapid session-revocation and patching mid-engagement once exploitation is detected.

---

## Disclosed CVEs & citations

### 1. CVE-2023-4966 ("CitrixBleed") — sensitive information disclosure via buffer overread
- **Affected:** NetScaler ADC/Gateway 13.0/13.1/14.1 configured as Gateway or AAA virtual server, prior to builds released 2023-10-10.
- **Disclosure:** Citrix security bulletin CTX579459 published 2023-10-10. Widely exploited in the wild within weeks; **CISA KEV** added 2023-11-21. Mandiant and multiple national CERTs (Australia's ACSC, the Dutch NCSC) published incident-response guidance documenting mass exploitation, including ransomware access-broker activity.
- **References:** https://support.citrix.com/article/CTX579459 ; https://www.cisa.gov/news-events/alerts/2023/11/21/cisa-and-partners-release-advisory-citrixbleed ; https://cloud.google.com/blog/topics/threat-intelligence/citrixbleed-exploitation

### 2. CVE-2025-5777 ("CitrixBleed 2") — memory overread in authentication/session handling
- **Affected:** NetScaler ADC/Gateway configured as Gateway or AAA virtual server, builds prior to the mid-2025 patch wave.
- **Disclosure:** Citrix security bulletin published mid-2025; independent researchers (watchTowr Labs among others) confirmed public exploitability and documented the parallel to the original CitrixBleed. Added to CISA KEV following confirmed in-the-wild exploitation.
- **References:** https://support.citrix.com/ (search CTX for the 2025-5777 bulletin — bulletin ID not stable-linked here, confirm current bulletin number at exploitation time) ; https://labs.watchtowr.com/ (CitrixBleed 2 research)

### 3. CVE-2019-19781 ("Shitrix") — pre-auth directory traversal → arbitrary code execution
- **Affected:** NetScaler ADC/Gateway 10.5, 11.1, 12.0, 12.1, 13.0, prior to the January 2020 patch wave.
- **Disclosure:** Reported to Citrix in December 2019; Citrix published mitigation guidance 2019-12-17 ahead of a full patch, an unusually long gap that drove mass pre-patch exploitation. **CISA** issued an alert (AA20-020A). Public exploitation was reported against multiple government and commercial targets within days of PoC publication in January 2020, with reporting linking activity to both opportunistic ransomware crews and nation-state actors.
- **References:** https://support.citrix.com/article/CTX267027 ; https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-020a

### 4. CVE-2023-3519 — pre-auth code execution (buffer overflow)
- **Affected:** NetScaler ADC/Gateway 13.0/13.1, specific configurations (Gateway, AAA virtual server, or certain load-balancing setups), prior to the July 2023 patch.
- **Disclosure:** Citrix bulletin CTX561482 published 2023-07-18. **CISA, NSA, and MS-ISAC** published a joint cybersecurity advisory (AA23-201A) documenting confirmed exploitation against a U.S. critical-infrastructure organization, including webshell deployment and post-exploitation AD reconnaissance. Added to CISA KEV.
- **References:** https://support.citrix.com/article/CTX561482 ; https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a

### 5. CVE-2022-27518 — unauthenticated remote code execution (SAML-configured appliances)
- **Affected:** NetScaler ADC/Gateway configured as a SAML SP or IdP, specific 12.1/13.0 builds prior to the December 2022 patch.
- **Disclosure:** Citrix bulletin CTX474995 published 2022-12-13, released out-of-band ahead of the normal patch cycle specifically because of active exploitation. The **NSA** published an advisory naming **APT5 (Manganese/UNC2630)**, a China-nexus actor, as exploiting this CVE against U.S. Department of Defense networks.
- **References:** https://support.citrix.com/article/CTX474995 ; https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3255051/

---

**Note on citation confidence:** Every CVE ID, patch-build timing, and named-actor attribution above reflects the author's best recollection of widely-reported public advisories current to early 2026. Exact bulletin IDs and patch-build numbers drift as vendors republish and consolidate advisories — **verify the live CTX bulletin number and current affected-build range against `support.citrix.com` before citing a specific build in a client deliverable.** Do not treat the build ranges above as authoritative for a live patch-gap determination.
