# Run 21 — owned executable-region integrity

Replaces the three 16-byte entry snapshots with SHA-256 baselines for the readable, non-writable
executable PT_LOAD segments of the SDK's own module. Captured after load/relocations, never persisted
across builds. Up to 8 segments and 16 MiB total; anything outside bounds is unavailable. Android
maps must confirm contiguous readable/executable/non-writable coverage before reading owned memory.
There are no JNI parameters accepting addresses or library paths. Other apps/processes are untouched.

Checks compare module layout, mapping permissions and all covered executable bytes. Inaccessible
maps or failed initial capture return UNAVAILABLE. Controlled host tests alter a dedicated fixture
library's permission/byte, observe detection, restore it and observe a clean comparison. The fixture
is not shipped. SHA-256 known-answer and range-parser tests accompany existing detector mutations.

Limitations: an initial modified image, hooked comparators/load metadata, a hostile kernel, or a
concurrent hostile unmapping can defeat in-process checks. No process-wide crash handler is installed.
This measures code change, not official package authenticity or whole-phone integrity. Read-only
non-executable data and other libraries are outside coverage. Do not assign cryptographic trust to
the boolean. No weights change. Physical Android behavior and overhead still require lab evidence.

Integration for Claude Run 14: native_code_modified retains its boolean/status keys; collector
version becomes 2. Describe its scope as owned executable segments, not whole-APK verification.
