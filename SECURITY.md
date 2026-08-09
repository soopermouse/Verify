# Jane Verify Security Model

1. Validator commands are trusted adapter code, never LLM/project text.
2. Validator execution uses `shell=False`.
3. JaneOS Capability Kernel authorizes project reads and execution.
4. Verify executes as delegated actor `jane.verify`.
5. Child processes receive a scrubbed environment.
6. Untrusted projects require Docker/Podman with network disabled, capabilities dropped, no-new-privileges, resource limits and read-only container root.
7. Timed-out containers are explicitly killed and removed.
8. SKIP never counts as PASS. Offline dependency-dependent checks remain SKIP.
9. Heuristic findings are advisory evidence and may contain false positives.
