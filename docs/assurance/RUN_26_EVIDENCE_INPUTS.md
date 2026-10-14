# Run 26: adversarial offline evidence inputs

Purpose: protect the integrity of the beta review process by rejecting ambiguous,
oversized and malformed input before it can become a report or review decision.
This extends the offline lab and beta tools; it does not add phone detectors.

## Findings reproduced before the fix
- Duplicate JSON fields were accepted with the last value winning, including schema
  and review/observation flags. Different readers could therefore interpret the same
  document differently.
- Unhashable enum fields and non-string timestamps escaped the validation contract
  as TypeError. Extremely large integer rate limits could raise OverflowError.
- Size checking used a stat followed by an unbounded read, and the observation-record
  CLI had no file-size bound.
- Calibration used platform-dependent epoch conversion. Very early valid timestamps
  can behave differently on Windows and Linux.

These are input-validation and evidence-quality issues in our own offline tooling.
They are not proof that external attackers can modify trusted release inputs, nor
a substitute for authenticating review documents and their operator declarations.

## Changes
The dedicated evidence_json reader rejects duplicate fields at every object level,
non-finite values (including overflowing exponents), invalid UTF-8, unpaired Unicode
surrogates, overlong integers, excessive depth and excessive node counts.
Reads request at most limit+1 bytes, even if a file grows after an earlier stat.

Limits: lab 16 MiB; observation and review 64 KiB each; JSON depth 32; one million
JSON value nodes; integer literals at most 128 characters. Schema-specific limits
remain stricter. Parsing has a bounded input size; it is not a streaming parser.

Lab enum validation rejects wrong types with ValueError. OS descriptions must be
valid UTF-8 text without ASCII control characters. Timestamps must be bounded,
timezone-aware ISO values representable in UTC; normalized observations use UTC.
Datetime comparison replaces platform-specific epoch conversion. Timestamps remain
operator declarations, not evidence that an observation was actually collected then.

Lab report/calibration APIs reject invalid candidate hashes explicitly. Policy-rate
validation checks numeric bounds before float conversion, avoiding integer overflow.
No signal keys, transcript protocol, snapshot schema, risk weights, migration,
lifecycle endpoint, Android packaging, signing configuration or CI YAML changes.

## Verification
The adversarial suite covers nested and Unicode-equivalent duplicate keys, byte/
structure budgets, non-finite numbers, malformed types, Unicode, timestamp conversion,
CLI exit codes and preservation of an existing lab file when a record is rejected.
A seeded 1,200-case wrong-type corpus checks that accepted observations remain safely
serializable and rejected ones use the documented error contract. The previous
assurance tests remain included. All positive samples are synthetic test fixtures.

The tests also distinguish schema validation from evidence authenticity: successful
parsing never promotes synthetic data or missing review into a physical test pass.
Beta review continues to require candidate-matched observations and human review.
Physical phone tests, live Google verification, accuracy calibration and beta release
approval remain unperformed by this run.

## Parallel integration
Based on frozen Run25 commit 2cd8d99936a9b7c11a96c1b157342c10fb670757.
Merge this isolated follow-up into Claude's integration/lifecycle stack when convenient.
Keep Claude's docs/BUILD_LOG.md as the ongoing build log; this document records only
Run26 scope and evidence. Claude was notified on integration PR15 before changes.
