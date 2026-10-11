# Mini-SOC Web — detection, triage and targeted retesting

An EMSI collective academic project (2025–2026) using a fictional PHP shop in a dedicated laboratory.

**Flow:** HTTP requests → PHP collector → MariaDB → Python detections → SOC triage console / NDJSON → Wazuh manager.

## Work demonstrated

- Pattern-based SQLi/XSS detection and correlation of repeated failed logins.
- Analyst status, justification and history, with session and CSRF checks.
- JSON events correlated with Wazuh alerts through event identifiers.
- Two investigation reports based on preserved lab evidence.
- HTTP checks and a targeted ZAP scan before/after selected SQLi/XSS fixes.

## Evidence and reading

- [Two SOC investigations](investigations/README.md): repeated login failures and a SQLi attempt.
- [Validation scope and published results](VALIDATION_20261009.md): test counts, evidence and remaining issues.
- [Analyst reading guide](LECTURE_ANALYSTE.md).
- [Wazuh integration](../integrations/wazuh/README.md).
- [French README with setup and verification commands](../README.md).

Wazuh/ZAP observations were obtained in separate local tests; the CI covers Python, PHP syntax, Docker integration and targeted HTTP retests. The application remains deliberately vulnerable for training. The ATT&CK mapping is indicative; a matching pattern is not proof of successful exploitation or compromise. No production detection rate or SLA is claimed.

**Team:** Anas El Karkouri, Omar Babba, Ilyas Ajelyan, Fadoua El-Allagui and Omar Gaga. **Supervisor:** Ismail Ait Lasri, EMSI. The original report describes collective attribution; subsequent repository work is not attributed retroactively to each member. Some components and documentation were prepared with AI assistance.
