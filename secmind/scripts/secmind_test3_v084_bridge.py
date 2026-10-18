"""SecMind v0.8.4 Test 3.0 entrypoint.

The hardened bridge implementation is shared with the v0.8.3 compatibility
entrypoint so fixes remain byte-identical across paired evaluations.  The
candidate manifest supplies a distinct ID, version and resolved runtime
profile; this thin entrypoint prevents another duplicate-ID registration.
"""

from __future__ import annotations

from secmind_test3_v083_bridge import main

if __name__ == "__main__":
    raise SystemExit(main())
