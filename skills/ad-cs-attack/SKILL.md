---
name: ad-cs-attack
description: "Active Directory Certificate Services (AD CS) abuse — STRICTLY the externally-reachable slice only. Covers ESC8 (NTLM relay to the AD CS HTTP Web Enrollment endpoint, /certsrv/), ESC1-style arbitrary-SAN certificate requests when Web Enrollment is internet-exposed, NDES/SCEP mobile-device-enrollment endpoint exposure (mscep.dll / mscep_admin challenge-password disclosure), and CRL/OCSP recon. Requires SOME authentication material (a leaked low-priv credential, a coerced/relayed NTLM auth, or a valid device-enrollment context) reaching an internet-facing AD CS HTTP endpoint — this is NOT internal Kerberos/BloodHound-style AD CS abuse (Certipy privesc chains, DCSync, golden certificates), which remains explicitly out of scope for this external-only bundle. Use when recon finds /certsrv/, /certsrv/mscep/mscep.dll, or a CA web-enrollment/NDES endpoint reachable from the internet."
sources: specterops-research, microsoft-advisories, public-research
report_count: 1
---

## Scope boundary — read this first

This bundle is explicitly **external-attack-surface only**. README.md lists "internal Active Directory attacks — BloodHound, Kerberoasting, DCSync, AD CS abuse, ntlmrelayx, PetitPotam" as out of scope, and that boundary stands. This skill exists **only** because a narrow slice of AD CS functionality — the HTTP-based enrollment endpoints — is sometimes deliberately exposed to the internet (mobile device management via NDES/SCEP, remote certificate self-service via Web Enrollment) and is therefore genuinely part of the external attack surface, not internal infrastructure reached after a foothold.

**Everything in this skill requires one of:**
- An internet-facing AD CS Web Enrollment HTTP endpoint (`/certsrv/`), reachable without VPN, and
- Some piece of authentication material that did NOT come from internal network access — e.g., a credential leaked/phished from a completely separate part of the engagement (a web app, a document, a breach corpus), or NTLM material relayed from a coercion primitive that itself operates over an externally-reachable protocol.

**STOP and hand off if:**
- The only path to AD CS is via an already-internal foothold (VPN, internal network segment, or a machine you already have code execution on). That is internal-AD-attack territory — out of scope. Hand off to the client's internal-RT process or tooling (Certipy, Certify, Rubeus).
- You are asked to perform Kerberoasting, DCSync, golden-certificate persistence, or any post-certificate PKINIT-to-domain-admin escalation. All of that is downstream of "you already have a domain foothold" and is explicitly out of this bundle's scope regardless of how the initial certificate was obtained.

This skill's job ends at "external attacker obtained a certificate they should not have." What that certificate is then used for internally is the client's internal-RT engagement, not this one.

---

## Recon — fingerprinting exposed AD CS HTTP surface

```bash
TARGET="pki.target.com"

# Web Enrollment (classic self-service cert request UI)
curl -sk "https://$TARGET/certsrv/" -I
curl -sk "https://$TARGET/certsrv/certrqxt.asp" -I     # advanced request form
curl -sk "https://$TARGET/certsrv/certfnsh.asp" -I     # request-submission handler (the ESC8 relay target)

# NDES / SCEP (mobile-device / MDM certificate enrollment — Intune-integrated
# deployments frequently expose this via Azure AD Application Proxy or a
# direct internet-facing endpoint by design)
curl -sk "https://$TARGET/certsrv/mscep/mscep.dll"
curl -sk "https://$TARGET/certsrv/mscep_admin/"        # admin/challenge-password endpoint — should NOT be internet-reachable

# CRL / OCSP (expected to be public — part of normal PKI validation, not
# itself a finding, but confirms a live CA hierarchy and leaks CA names)
curl -sk "https://$TARGET/CertEnroll/" | grep -oE '[A-Za-z0-9_-]+\.crl'
```

A `401 Unauthorized` (rather than a redirect to a corporate SSO login) on `/certsrv/` is the key signal — it means the endpoint expects **Windows Integrated Authentication (NTLM/Kerberos over HTTP)** directly, not a modern federated login, which is exactly the precondition ESC8 needs.

---

## ESC8 — NTLM relay to AD CS Web Enrollment

**The core issue:** By default, IIS-hosted AD CS Web Enrollment (`/certsrv/`) does not enable **Extended Protection for Authentication (EPA)** / channel binding, and accepts NTLM authentication over HTTP. NTLM authentication has no inherent protection against relay — a captured NTLM authentication attempt (from anywhere the attacker can position for relay) can be forwarded to this endpoint instead of its intended destination, and the endpoint will treat it as a legitimate authenticated request from the victim whose NTLM material was relayed.

**Why this is externally relevant (not just an internal-network technique):** If the Web Enrollment endpoint is internet-facing, an attacker who has obtained NTLM authentication material through any means reachable from outside the internal network — a phished credential capture, a leaked NTLM hash from an unrelated external finding, or (with explicit engagement authorization) a coercion primitive that itself triggers over an externally-reachable protocol — can relay directly to the public endpoint without ever touching the internal network path.

**Attack flow (once relay-capable auth material is available and in-scope):**
1. Relay the captured/coerced NTLM authentication to `POST https://$TARGET/certsrv/certfnsh.asp`, requesting a certificate using a template that permits client authentication (commonly the default `User` or `Machine` template).
2. The issued certificate is bound to whatever identity the relayed authentication represented — if the coerced/relayed identity is a privileged account or a domain controller's machine account, the resulting certificate grants that identity's authentication rights.
3. The certificate itself is the deliverable of this skill's scope. Using it for **PKINIT authentication to obtain a TGT, and anything downstream (DCSync, lateral movement)** is internal-AD-attack tradecraft — hand off per the scope boundary above.

**Validate, don't assume:** Confirm `/certsrv/` returns `401` with `WWW-Authenticate: NTLM` or `Negotiate` (not a redirect to modern SSO) before treating ESC8 as applicable — many organizations front Web Enrollment with a reverse proxy that terminates NTLM and re-authenticates via SAML/OIDC, which closes this specific path even though the underlying template misconfiguration may still exist.

---

## ESC1-style arbitrary-SAN requests via exposed Web Enrollment

If a certificate template both (a) permits low-privileged users to enroll, and (b) allows the **requester to supply the Subject Alternative Name (SAN)** on the request rather than having the CA populate it from the requester's own AD attributes, then any authenticated requester — including one authenticating with low-privilege material obtained externally — can request a certificate for an **arbitrary UPN**, e.g. a domain administrator's account.

- Check via the Web Enrollment advanced request form (`/certsrv/certrqxt.asp`): if the form or its underlying CertSrv API accepts a raw CSR and does not strip/validate SAN extensions supplied in that CSR against the authenticated requester's actual identity, the template is misconfigured this way.
- This requires *some* valid low-privilege authentication to the endpoint (not a fully unauthenticated attack) — the value here is that low-priv creds obtained from a completely unrelated part of the external engagement (e.g., a credential-stuffing hit, a leaked password from a separate app) can be escalated to "certificate for any UPN" if this specific template misconfiguration exists on an internet-facing CA.
- As with ESC8, the resulting certificate's use for PKINIT/domain authentication is out of this skill's scope — flag the misconfigured template and the successfully-issued arbitrary-SAN certificate as the finding, and hand off further use.

---

## NDES/SCEP challenge-password exposure

Microsoft explicitly documents exposing NDES to the internet via Azure AD Application Proxy for Intune-managed device certificate enrollment — this is a **supported, common configuration**, not automatically a misconfiguration. The risk is in a specific, well-documented follow-on mistake:

- NDES issues a **one-time SCEP challenge password** via the `/certsrv/mscep_admin/` endpoint, intended to be retrieved only by the MDM server (Intune) on the device's behalf, then relayed to the device out-of-band.
- If `/certsrv/mscep_admin/` itself is reachable from the internet (rather than being restricted to the MDM server's IP or requiring separate strong authentication), an external attacker can retrieve a valid challenge password directly and use it to request a device certificate through `mscep.dll` without ever going through the intended MDM enrollment flow.
- **Detection:** `curl -sk https://$TARGET/certsrv/mscep_admin/` returning anything other than a `401`/`403` (or a page that clearly requires separate strong admin auth) on an internet-reachable host is the finding — report as High/Critical regardless of whether you complete a full SCEP request, since the challenge-password disclosure alone is a meaningful authentication-bypass primitive for that CA's device-enrollment flow.

---

## What is explicitly NOT in this skill

- ESC2 through ESC7, ESC9 through ESC16 as internal privilege-escalation primitives (vulnerable-template abuse, weak CA ACLs, `CT_FLAG_NO_SECURITY_EXTENSION`, cross-forest issues, and similar) — these are real, well-documented (the original "Certified Pre-Owned" taxonomy plus later community additions), but they all presuppose you already hold a domain-authenticated foothold and are enumerating templates/CA config from inside — internal-AD-attack territory.
- PKINIT abuse, `Rubeus asktgt /certificate`, `Certipy auth`, or any tool/technique that turns an obtained certificate into a Kerberos ticket — downstream of this skill's scope.
- Golden/silver certificate persistence, CA private-key theft, DCSync via a stolen CA certificate — post-compromise persistence, out of scope per the bundle's stated boundary.
- Coercion primitives themselves (PetitPotam, PrinterBug, etc.) as a means to *generate* NTLM material to relay — those operate over internal SMB/RPC protocols and are internal-network techniques; this skill only covers what happens once relay-capable material reaches the externally-exposed endpoint.

---

## Severity scoring guidance

| Finding | Severity |
|---|---|
| `/certsrv/` internet-reachable, EPA enabled, no template misconfiguration found | Informational (attack-surface note) |
| `/certsrv/` internet-reachable, EPA disabled (NTLM relay viable), relay-capable auth material in scope | **Critical** — arbitrary certificate issuance for a relayed/coerced identity |
| Low-priv external creds + arbitrary-SAN template confirmed via Web Enrollment | **Critical** — certificate for arbitrary UPN including privileged accounts |
| `mscep_admin` challenge-password endpoint internet-reachable without separate auth | **Critical** — device-enrollment authentication bypass primitive |
| NDES/SCEP present, `mscep_admin` properly restricted | Informational — expected/supported exposure pattern, not a finding |

---

## Anti-patterns

- **DO NOT perform internal coercion (PetitPotam, etc.) to manufacture NTLM material** unless that is explicitly separately in scope as an internal-network technique — this skill covers what to do with relay-capable material once you have it via an in-scope external path, not how to generate it via internal-only primitives.
- **DO NOT continue past "certificate obtained" into PKINIT/TGT territory** — that is a scope violation of this bundle's external-only boundary, not just this skill's.
- **DO NOT assume every `/certsrv/` hit is exploitable** — confirm the `401`/`WWW-Authenticate: NTLM` signal and the specific template misconfiguration before claiming ESC8 or ESC1; many exposed Web Enrollment instances are correctly hardened.
- **DO NOT report generic "AD CS abuse" findings** — always scope the finding to the specific externally-reachable primitive (relay-to-Web-Enrollment, arbitrary-SAN template, or challenge-password disclosure), since that framing is what keeps this within the bundle's stated boundary and what the client's triage team will expect from an external engagement.

---

## Related Skills & Chains

- **`m365-entra-attack`** — organizations that federate/hybrid-join AD to Entra ID sometimes expose NDES via Azure AD Application Proxy for Intune; recon overlap between the two skills is common on hybrid-identity engagements.
- **`hunt-auth-bypass`** — the general SSO/token-trust taxonomy this skill's NTLM-relay and challenge-password-disclosure findings are specific instances of; use that skill's severity/validation framing for writing up the finding.
- **`enterprise-vpn-attack`** — if the same organization also exposes a VPN appliance, a relayed AD credential obtained here may also be validly tested against that appliance's AAA backend (with separate scope confirmation).
- **`redteam-mindset`** — the scope-boundary discipline in this skill (stop at "certificate obtained," do not continue into internal PKINIT/DCSync territory) is a direct application of that skill's external-only operator discipline.

---

## Disclosed research & citations

### 1. "Certified Pre-Owned: Abusing Active Directory Certificate Services" — foundational research defining the ESC1-ESC8 taxonomy
- **Authors:** Will Schroeder and Lee Christensen, SpecterOps.
- **Published:** June 17, 2021. Defined the original eight AD CS escalation/persistence primitives (ESC1-ESC8), including ESC8's NTLM-relay-to-Web-Enrollment technique that this skill's externally-reachable content is built on. Later community research (multiple independent authors, 2022-2024) extended the taxonomy through ESC9-ESC16, covering additional CA-configuration and cross-forest primitives not covered by this skill's external-only scope.
- **References:** https://posts.specterops.io/certified-pre-owned-d95910965cd2 ; the accompanying whitepaper PDF is linked from that post.

### 2. CVE-2022-26923 ("Certifried") — machine-account attribute spoofing certificate-mapping privilege escalation
- **Note on scope:** This CVE is an **internal** privilege-escalation primitive (any authenticated low-priv domain user to domain admin, via `dNSHostName`/SAM-name manipulation on a self-owned machine account) — included here only as background context for why Microsoft changed default certificate-to-account mapping behavior; the escalation itself requires internal domain authentication and is out of this skill's external-only scope.
- **Discovery:** Reported by Oliver Lyak (ly4k). Microsoft published the advisory and a corresponding patch (strengthening certificate-mapping enforcement) on 2022-05-10, tracked as CVE-2022-26923.
- **References:** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923 ; https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4

---

**Note on citation confidence and scope discipline:** The ESC-primitive names and general mechanisms above reflect well-established public research current to early 2026. Because this skill deliberately narrows a normally internal-AD-attack topic to its external-reachable slice, err on the side of stopping and asking before treating any AD CS finding as in-scope if the reachability path is unclear — the cost of wrongly scoping an internal AD CS finding as "external" is a real engagement-boundary violation, not just an inaccurate report.
