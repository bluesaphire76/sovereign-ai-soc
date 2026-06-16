# AI SOC Security Knowledge Base

This knowledge base provides local SOC playbook context for Qdrant-backed semantic retrieval and RAG-enabled AI workflows.

Qdrant is used only as a semantic memory and decision-support layer. It must not be used as the primary source for severity decisions, operational deduplication, automatic noise suppression, incident closure or replacement of deterministic correlation rules.

---

## SSH Brute Force Investigation Playbook

Use this playbook when an incident shows repeated failed SSH authentication attempts, suspicious login activity or brute-force indicators.

Typical indicators:

- multiple failed SSH login attempts from the same source IP;
- failed login attempts against privileged or common usernames;
- authentication failures followed by a successful login;
- repeated access attempts across a short time window;
- source IP not previously observed in the environment.

Analyst checks:

1. Review the source IP address and determine whether it is internal, external, known or expected.
2. Check whether any successful authentication happened after the failed attempts.
3. Identify the targeted user accounts.
4. Review the affected host for privilege escalation, sudo activity or new processes after the login window.
5. Check whether similar SSH brute force incidents were observed previously.
6. Decide whether the incident is a true positive, benign scanner activity or an approved test.

Recommended response:

- increase monitoring on the affected account and host;
- rotate credentials if a successful login occurred;
- block or restrict the source IP only after human approval;
- open a case if there is evidence of successful access, lateral movement or privilege escalation.

Decision boundary:

SSH brute force similarity retrieved through Qdrant is contextual support only. It must not automatically confirm compromise or determine final severity.

---

## Sudo Privilege Escalation Review Playbook

Use this playbook when an incident includes suspicious sudo activity, privilege escalation indicators or unexpected administrative commands.

Typical indicators:

- sudo command executed by a non-standard user;
- sudo activity outside normal maintenance windows;
- package installation or service modification after sudo;
- privilege escalation after authentication anomalies;
- repeated sudo attempts or denied sudo usage.

Analyst checks:

1. Identify the user, host, command and timestamp.
2. Verify whether the activity matches an approved maintenance or operational task.
3. Review preceding authentication activity.
4. Review following process, package, service or file changes.
5. Check whether the user normally performs administrative operations.
6. Compare with similar historical incidents or known false-positive patterns.

Recommended response:

- document whether the sudo action was authorized;
- create a case action if ownership or approval is unclear;
- escalate if sudo activity follows suspicious login activity;
- consider detection tuning only if the event is confirmed as recurring operational noise.

Decision boundary:

Qdrant may retrieve similar sudo cases or procedures, but final classification must remain analyst-led and supported by deterministic evidence.

---

## Suricata Suspicious DNS Investigation Playbook

Use this playbook when Suricata or network telemetry reports suspicious DNS activity, unusual domains, DNS tunneling indicators or suspicious name resolution patterns.

Typical indicators:

- unusual DNS query volume;
- long or random-looking domain names;
- DNS queries associated with threat intelligence;
- repeated failed lookups for suspicious domains;
- DNS activity without clear endpoint compromise evidence;
- Suricata alerts correlated with DNS telemetry.

Analyst checks:

1. Identify source host, queried domain, timestamp and alert signature.
2. Review whether the domain is internal, approved, known SaaS or external.
3. Check whether endpoint telemetry shows compromise, malware, suspicious process execution or persistence.
4. Review related network events around the DNS activity.
5. Search for similar historical Suricata or DNS incidents.
6. Determine whether the activity is malicious, suspicious but unconfirmed, benign, or a false positive.

Recommended response:

- enrich the domain with threat intelligence if available;
- monitor the source host for follow-up activity;
- open a case if DNS activity correlates with endpoint compromise or repeated suspicious behavior;
- avoid automatic containment when DNS evidence is isolated and unconfirmed.

Decision boundary:

Suspicious DNS context retrieved by Qdrant is not sufficient to confirm endpoint compromise. Deterministic evidence and analyst review are required.

---

## False Positive Case Closure Policy

Use this procedure when an incident or case may be closed as a false positive.

Required conditions:

- the alert was reviewed by an analyst;
- supporting evidence was checked;
- the reason for false positive classification is documented;
- any related detection tuning or exception is reviewed separately;
- there is no unresolved evidence of compromise;
- closure does not hide recurring operational risk.

Recommended closure fields:

- root cause;
- reviewed evidence;
- false-positive rationale;
- residual risk;
- related tuning recommendation, if applicable;
- analyst name and review timestamp.

Examples of valid false-positive reasons:

- approved maintenance activity;
- expected administrative operation;
- known scanner or lab validation;
- benign software update;
- detection rule too broad but no malicious activity found.

Decision boundary:

Qdrant can retrieve previous false-positive examples and closure guidance, but must not automatically close incidents or cases.

---

## Noise Suppression and Exception Tuning Guidance

Use this guidance when recurring alerts create operational noise and may require suppression, exception tuning or detection control review.

Valid tuning candidates:

- recurring low-value operational events;
- known approved administrative activity;
- repeated maintenance events;
- noisy rules with documented business justification;
- false positives validated through analyst review.

Required checks before tuning:

1. Confirm the event is recurring and low-value.
2. Verify that the scope is narrow enough.
3. Confirm business justification and owner.
4. Define expiration or review date.
5. Validate that suppression does not hide meaningful attack behavior.
6. Keep audit history and rollback capability.

Unsafe tuning examples:

- broad host-wide suppression without justification;
- user-wide suppression for privileged accounts;
- suppression of high-severity alerts without approval;
- automatic suppression based only on semantic similarity;
- disabling correlation logic because a previous incident looked similar.

Decision boundary:

Qdrant may suggest similar suppression examples or related procedures, but Detection Control Plane validation, RBAC and human approval remain authoritative.

---

## Incident Similarity Review Guidance

Use semantic similarity to support historical investigation, not to make final decisions.

Useful similarity signals:

- same host or asset group;
- same rule or alert type;
- similar MITRE technique;
- similar authentication pattern;
- similar network behavior;
- similar analyst decision or case closure rationale.

Limitations:

- semantically similar incidents may have different risk;
- similar wording does not prove same root cause;
- historical false positives do not guarantee current benign activity;
- similarity must be validated against deterministic evidence.

Analyst use:

- compare the new incident with retrieved historical context;
- identify repeated patterns;
- reuse relevant investigation steps;
- check whether previous tuning exists;
- document why the current case is similar or different.

Decision boundary:

Semantic similarity is context. It is not operational deduplication, final classification or severity assignment.

---

## Case Escalation and Closure Readiness

A case should remain open when:

- ownership is unclear;
- evidence review is incomplete;
- recommended actions are unresolved;
- severity has not been reviewed;
- containment or remediation status is unknown;
- closure approval is missing.

A case can move toward closure when:

- evidence was reviewed;
- root cause or false-positive rationale is documented;
- recommended actions are completed or explicitly deferred;
- residual risk is documented;
- closure approval is recorded where required.

Decision boundary:

Qdrant may retrieve closure policy or similar cases, but case closure must remain human-approved and audit-backed.
