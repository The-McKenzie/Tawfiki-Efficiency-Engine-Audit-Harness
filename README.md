\# Tawfiki Efficiency Engine Audit Harness

Version: tee-harness-1.1



Copyright (C) 2026 Rodger McKenzie / Tawfiki AI. All rights reserved.

Released for audit review and critique purposes only.

No license is granted to modify, distribute, or use this file outside of an authorized audit engagement.



\## What This Is



A behavioral audit harness for a closed-source AI structural index engine.

Retention verdicts computed from input bytes and reconstruction output bytes alone

for all non-code domains. The engine is never consulted for retention verdicts

outside the code domain.



OWASP identifies risks. MITRE models threats. TEE proves results.



\## Suites



| Suite | Description | Pre-Registered Threshold |

|-------|-------------|--------------------------|

| D8    | Null Build Gate | All verdict fields must fail in null mode |



\## Sealed Audit Results



The following results are from a separate sealed witnessed audit run and are

not suites implemented in this public harness:



| Audit | Description | Sealed Result |

|-------|-------------|---------------|

| A002  | Structural Index Efficiency | 2,000x verified lower bound at 1MB scale |



\## Honesty Rules



\- Retention verdicts for all non-code domains are computed from input bytes 

&#x20; and reconstruction output bytes alone. The engine is never consulted for 

&#x20; these verdicts.

\- Code domain verdicts compare engine-reported per-file reconstruction content 

&#x20; against original files. This is a disclosed methodology limitation noted for 

&#x20; reviewer awareness.

\- Efficiency metrics (A and B) are reported separately and never fused 

&#x20; into a verdict. They are measurements, not grades.

\- Fraud detection: the incompressible control submits high-entropy input 

&#x20; to the engine. A genuine structural index engine must achieve byte-exact 

&#x20; reconstruction on this input — entropy does not degrade reconstruction 

&#x20; fidelity. If reconstruction fails on high-entropy input, the engine is 

&#x20; not functioning as claimed. The harness voids the run.

\- The D8 null build gate proves the harness would catch a trivially 

&#x20; bypassed engine. If any verdict field passes in null mode the harness 

&#x20; itself is broken.

\- VOID is a first-class outcome distinct from FAIL:

&#x20;   FAIL = engine genuinely failed a suite

&#x20;   VOID = audit itself is invalid (control failure, chain break)

\- Timestamps are informational only. Chain ordering guaranteed by prev\_seal.



\## Witness Protocol



This harness is designed for witnessed live execution.

Remote runs are not supported because the engine binary is proprietary and not included.



1\. Witness receives harness.py and prereg template before the session.

2\. Witness supplies or co-generates the audit salt at ceremony time.

3\. Corpus generates deterministically from salt in front of witness.

4\. Witness leaves with run.jsonl, prereg.json, and harness.py.



\## Provenance



The published harness file SHA-256 is committed in prereg.json.

Verification uses those exact bytes.

Any deviation between the reviewed harness and the run harness is detectable

via sha256(harness.py) in the meta record of run.jsonl.



\## Requesting a Witnessed Run



The engine binary is proprietary and not included in this repository.

Third-party witnessed runs are coordinated directly.

Contact: Rodger McKenzie / Tawfiki AI



\## Read the Full Methodology







Rodger McKenzie -- Tawfiki AI / TAIOS

