# Privacy Policy

**Last updated: september 2026**

This Privacy Policy explains how cerbere Inc ("Cerbere", "we", "us", "our")
collects, uses, and protects information when you use Cerbere-AG (also referred to as
AgentGuard), our runtime security and observability platform for AI agents (the
"Service").

This document is a starting point drafted from the actual functionality of the
Service. It is not legal advice. Have it reviewed by a lawyer, particularly if you
serve users in the EU/EEA (GDPR), the UK (UK GDPR), or California (CCPA/CPRA),
before publishing it.

---

## 1. Who we are

cerbere Inc, located at kinshasa, democratique republic of congo, operates Cerbere-AG. For any
question about this policy or your data, contact us at hello@cerbereag.site.

## 2. What information we collect

### 2.1 Account information
When you sign in via magic link, Google, or GitHub, we receive and store:
- Your email address
- Your display name and, where provided by the identity provider, a profile
  picture
- A unique account identifier
- Which sign-in method you used (email, Google, or GitHub)

### 2.2 Organization and team information
Cerbere is multi-tenant: your account belongs to an organization ("org") within a
workspace ("tenant"). We store the organization/workspace name, the members
associated with it, and each member's role (e.g. admin, developer, viewer).

### 2.3 Agent runtime data ("spans")
The core function of the Service is to monitor AI agents you connect to it. Each
time a monitored agent makes an LLM call or a tool call, we receive and store a
"span" record, which can include:
- The input sent to the LLM or tool (e.g. a prompt, a function-call payload)
- The output returned
- Token counts and estimated cost
- Latency and timestamps
- The results of our automated security checks on that call (e.g. prompt-injection
  detection, PII/secret detection, policy decisions, risk scores)
- Identifiers for the agent, trace, and organization that produced the span

**Because span content can include whatever your agents send or receive, it may
contain personal data or confidential information originating from your own users
or systems.** You are responsible for ensuring you have the right to send that
content through the Service, and for configuring the Service's redaction and
policy features appropriately for your use case.

### 2.4 Automated content redaction
Before certain span content is stored or forwarded to third-party services (see
Section 4), we run automated detection to identify and redact patterns
resembling secrets (API keys, credentials, tokens) and common PII (emails, phone
numbers, government ID numbers, payment card numbers). This process is
best-effort and pattern-based; it reduces but does not eliminate the risk that
sensitive content is stored or transmitted. Do not rely on it as your sole
safeguard for highly sensitive data.

### 2.5 Audit logs
Administrative and security-relevant actions (logins, agent creation/revocation,
policy changes, access-control decisions) are recorded in an audit log for
security and compliance purposes.

### 2.6 Technical and usage data
We automatically collect IP address, browser/device information, timestamps, and
usage patterns (e.g. which dashboard pages you view, API endpoints called)
through standard server logging.

### 2.7 Cookies
We use a single, essential, httpOnly session cookie to keep you signed in. We do
not use advertising or third-party tracking cookies. See Section 8.

## 3. How we use information

We use the information above to:
- Authenticate you and maintain your session
- Operate the Service's core function: analyzing agent activity for security
  risks and providing observability (dashboards, traces, audit trail)
- Enforce the security policies you configure (tool allow/deny lists, budget
  limits, approval workflows)
- Detect, investigate, and prevent abuse, fraud, or security incidents
- Provide customer support
- Maintain and improve the Service's detection accuracy
- Meet legal and compliance obligations
- Send you service-related communications (e.g. sign-in links, security alerts)

We do not sell your personal information, and we do not use your span content to
train models for other customers.

## 4. Who we share information with

We share information with the following categories of third parties, only as
needed to operate the Service:

- **Authentication provider (Supabase):** processes sign-in via magic link,
  Google, and GitHub, and stores your authentication identity.
- **Hosting and database providers:** the Service and its database are hosted
  with infrastructure providers (currently Render and Supabase/PostgreSQL), who
  store data on our behalf under their own security commitments.
- **Automated security analysis providers:** when deeper risk analysis is
  needed, span content may be sent to third-party LLM providers acting as an
  automated "judge" to classify risk (e.g. prompt injection, policy violations).
  We apply redaction before this step where feasible (see Section 2.4).
- **Identity providers (Google, GitHub):** if you sign in with Google or GitHub,
  those providers process your authentication on their end according to their
  own privacy policies.
- **Legal and safety:** we may disclose information if required by law, legal
  process, or to protect the rights, property, or safety of Cerbere, our users,
  or others.
- **Business transfers:** if Cerbere is involved in a merger, acquisition, or
  asset sale, your information may be transferred as part of that transaction.

We do not share your data with third parties for their own marketing purposes.

## 5. Data retention

We retain account information for as long as your account is active. Span data,
audit logs, and related records are retained for [RETENTION PERIOD — e.g. "90
days by default, or as configured on your plan"] to support the Service's
security and observability functions, unless a longer period is required by law
or a signed agreement with you. You can request deletion of your account and
associated data as described in Section 7.

## 6. International data transfers

Depending on your location and the location of our hosting providers, your
information may be transferred to and processed in countries other than your
own, including the United States. Where required, we rely on appropriate
safeguards (such as standard contractual clauses) for such transfers.
[Confirm and adjust once your hosting regions are finalized.]

## 7. Your rights

Depending on where you live, you may have rights to access, correct, export, or
delete your personal data, or to object to or restrict certain processing. To
exercise these rights, contact us at hello@cerbereag.site. We will respond
within the timeframe required by applicable law.

If you are in the EU/EEA or UK, you also have the right to lodge a complaint
with your local data protection authority.

## 8. Cookies

We use one essential session cookie (`cerbere_session`) to keep you signed in
after a successful login. It is httpOnly (not readable by page scripts) and
expires automatically. We do not currently use analytics, advertising, or
cross-site tracking cookies. If that changes, this section will be updated and,
where required, we will ask for your consent first.

## 9. Security

We apply technical and organizational measures to protect your data, including
encrypted connections (HTTPS), hashed credentials, role-based access control,
and audit logging. No system is fully secure, and we cannot guarantee absolute
security.

## 10. Children's privacy

The Service is intended for business use and is not directed to individuals
under 18. We do not knowingly collect personal information from children.

## 11. Changes to this policy

We may update this Privacy Policy from time to time. We will update the "Last
updated" date above and, for material changes, provide additional notice (e.g.
by email or in-app notification).

## 12. Contact us

cerbere Inc 
kinshasa, democratique republic of congo
hello@cerbereag.site
