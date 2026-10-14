# Corrected P12 software acceptance

The reports in this folder passed at `d53b90f1ee3398ea0c784becdd1557e2eac78bd2`, complete clean tree `e6fb1363c2398e5dd4c5182a6709a95720602e14`.
acceptance.json identifies all twenty-two mandatory jobs, downloaded ZIP digests
and independently verified raw Git input hashes. Raw report files are retained
byte-for-byte. The final documentation head is tested again and its implementation
input arrays compared to these accepted receipts before ordinary guarded merge.

The initial 4d6f3c9 reports remain unchanged in initial/. A later final-head run
exposed the foreground-read/snapshot publication race; the current implementation
fixes it and preserves exact immutable witness checks while replacing only local
cache addresses. Eleven portable sync tests include the actual interleave.

Physical iPhone/packaged WebView2, mobile memory and qualified-review gates remain
open. A software receipt, saved environment draft, Publish and independently
observed restoration are separate outcomes.
