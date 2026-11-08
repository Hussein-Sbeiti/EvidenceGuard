# Project To-do List

## Scanner quality

- [ ] Add positive and negative test cases for every detection rule.
- [ ] Review findings against labeled examples and record false positives and missed issues.
- [ ] Add clear CWE names and explanations for every rule.
- [ ] Check multiline code and common formatting variations where line-based matching misses patterns.

## Useful capabilities

- [ ] Integrate with official vulnerability/advisory APIs, starting with OSV for package versions and NVD for CVE metadata.
- [ ] Check whether an approved Exploit-DB API or feed is available; if used, retain references and metadata only, not exploit code or payloads.
- [ ] Make online lookups opt-in, explain what is sent, and send package names/versions or identifiers only—not uploaded source code.
- [ ] Cache advisory responses with source, retrieval date, and record identifier so results can be refreshed and traced.
- [ ] Add an optional local AI model to explain findings; clearly distinguish model output from verified rule results.
- [ ] Keep fix suggestions as recommendations; do not modify uploaded files automatically.

## AI agent training and evaluation

- [ ] Define a narrow agent task: explain scanner findings and suggest defensive fixes for human review.
- [ ] Build a labeled training/evaluation dataset from permitted, documented sources and reviewed examples.
- [ ] Store each run's model/version, rule or finding ID, input reference, generated output, timestamp, and dataset/source version.
- [ ] Label outcomes as true positive, false positive, true negative, or false negative against reviewed ground truth.
- [ ] Record a documented reward/score for each run, including correctness, useful evidence/line references, and safe, relevant remediation.
- [ ] Keep reviewer feedback and reward rationale so scores can be audited; do not treat unreviewed model confidence as ground truth.
- [ ] Separate training, validation, and held-out test data to prevent leakage; report precision, recall, and false-positive rate.
- [ ] Compare the agent to the existing deterministic rules and keep an easy way to disable the model.
- [ ] Exclude secrets, personal data, unlicensed content, and exploit payloads from stored training records.

## App experience and safety

- [ ] Show skipped files and upload limits clearly in the results.
- [ ] Add a way to export findings as JSON or a readable report.
- [ ] Review upload limits, error messages, and local-only behavior as features are added.
- [ ] Keep the interface usable on mobile and with keyboard navigation.

## Project delivery

- [ ] Document setup and run instructions for Windows, macOS, and Linux.
- [ ] Add a small, clearly labeled demo project for repeatable scans.
- [ ] Record test results and limitations in the school-project presentation.
- [ ] Push local commits to GitHub after reviewing the diff.
