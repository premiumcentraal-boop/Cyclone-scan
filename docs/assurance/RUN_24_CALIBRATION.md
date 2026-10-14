# Run 24 — descriptive calibration and performance tooling

    python -m tools.assurance.calibration lab.json --revision <git-sha> --apk-sha256 <apk-sha256>

The evaluator filters to the exact revision/APK, excludes synthetic/unreviewed observations, and
uses the latest scenario per stable device alias. Incomplete/error/unknown-ground-truth scenarios
are excluded from accuracy denominators but remain visible in coverage/crash counts. Clean-device
intervention and altered-condition miss rates are separate, aggregated by device alias using any
error across its included scenarios. Empty cohorts report null, not 0% error. Latency p50/p95 and
descriptive Wilson intervals are included with explicit sample/correlation caveats.

Hard failures always block the score-policy proxy regardless of candidate thresholds. The tool
does not modify production weights, thresholds or shared risk vectors. Defaults require at least
5 distinct clean and 3 altered-condition aliases merely to mark data READY_FOR_REVIEW; that is not
a production accuracy guarantee or completed calibration. Ground truth remains operator-declared.

Current measured calibration: INSUFFICIENT_DATA. There are no physical observations in this run.
No detection rate, false-positive rate or battery/latency claim for real phones is asserted. Execute
the matrix and review representative strata before tuning any enforced policy.
