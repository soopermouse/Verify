from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Callable, Any

from janeos.kernel.capabilities import CapabilityRequest
from janeos.kernel.authorization import AuthorizationEngine, AuthorizationError

from jane_verify.models import CheckResult, ReviewStatus, ToolCommand
from .sandbox import ContainerSandbox, ProjectTrust, SandboxPolicy, ScrubbedEnvironment


class SafeCommandRunner:
    """Execute trusted Jane Verify adapter commands under an authority boundary.

    Security properties:
      * shell=False; no shell command interpretation.
      * Executables come from a fixed allowlist and adapter code, never model text.
      * The JaneOS Capability Kernel authorizes execution before launch.
      * Child processes receive a scrubbed environment, never Jane's full env.
      * UNTRUSTED repositories may execute only in a network-disabled container;
        Jane Verify refuses host fallback if Docker/Podman is unavailable.
      * Untrusted repositories execute from a disposable copy, not the user's
        source tree.

    TRUSTED mode intentionally means "the developer trusts this repository".
    It is still injection-safe and secret-scrubbed, but it does not claim OS
    isolation from hostile project code.
    """

    ALLOWED_EXECUTABLES = {
        "php", "composer", "vendor/bin/phpunit", "vendor/bin/phpstan", "vendor/bin/psalm",
        "bin/console", "npm", "npx", "node", "python", "python3", "pytest", "ruff", "mypy",
        "bandit", "mvn", "gradle", "gradlew", "dotnet"
    }

    def __init__(
        self,
        timeout_seconds: int = 120,
        *,
        authorization: AuthorizationEngine | None = None,
        actor: str = "jane.verify",
        security_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.authorization = authorization
        self.actor = actor
        self.security_event = security_event

    @staticmethod
    def _execution_resource(root_path: Path) -> str:
        return f"project:{root_path.as_posix()}"

    def _require_execution_authority(self, root_path: Path, spec: ToolCommand) -> None:
        if self.authorization is None:
            raise PermissionError("Jane Verify execution requires the JaneOS Capability Kernel")
        self.authorization.require(
            CapabilityRequest(
                capability="review.validator.execute",
                provider_id="jane.verify",
                resource=self._execution_resource(root_path),
                actor=self.actor,
                purpose="deterministic code validation",
                metadata={"validator": spec.name, "category": spec.category},
            )
        )

    def _resolve_host_argv(self, root_path: Path, spec: ToolCommand) -> tuple[list[str] | None, str | None]:
        exe = spec.argv[0]
        if exe not in self.ALLOWED_EXECUTABLES:
            return None, "executable not allowlisted"
        resolved = root_path / exe if "/" in exe else None
        if resolved is not None:
            if not resolved.exists():
                return None, "tool not installed in project"
            return [str(resolved), *spec.argv[1:]], None
        found = shutil.which(exe)
        if not found:
            return None, "tool not installed"
        return [found, *spec.argv[1:]], None

    @staticmethod
    def _copy_untrusted_project(root_path: Path, destination: Path) -> Path:
        workspace = destination / "workspace"
        # Ignore VCS metadata and local Jane state. Dependencies are intentionally
        # copied because network is disabled and validators may need installed deps.
        shutil.copytree(
            root_path,
            workspace,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", ".jane", "jane_state.json", "jane_review_history.json"),
        )
        return workspace


    @staticmethod
    def _terminate_container(runtime: str, container_name: str, env: dict[str, str]) -> bool:
        """Best-effort hard termination after a host-side timeout.

        Killing the docker/podman client does not guarantee that the container
        stopped, so Jane explicitly kills and removes the named container.
        """
        try:
            subprocess.run(
                [runtime, "kill", container_name],
                capture_output=True, text=True, timeout=10, shell=False, env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            completed = subprocess.run(
                [runtime, "rm", "-f", container_name],
                capture_output=True, text=True, timeout=10, shell=False, env=env,
            )
            # docker/podman may report "no such container" after --rm; that is
            # also confirmation that the container no longer exists.
            stderr = (completed.stderr or "").lower()
            return completed.returncode == 0 or "no such container" in stderr or "not found" in stderr
        except (OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _offline_dependency_skip(root_path: Path, spec: ToolCommand) -> str | None:
        """Return a clear SKIP reason when an isolated offline run cannot restore deps."""
        exe = spec.argv[0]
        if exe in {"npm", "npx"} and not (root_path / "node_modules").exists():
            return "offline sandbox: node_modules is not vendored; dependency-dependent check skipped (not passed)"
        if exe in {"mvn", "gradle", "gradlew"}:
            return "offline sandbox: Java dependency restore/cache is unavailable; check skipped (not passed)"
        if exe == "dotnet" and not any(root_path.rglob("project.assets.json")):
            return "offline sandbox: .NET restore assets are not present; check skipped (not passed)"
        return None

    def run(
        self,
        root: str | Path,
        spec: ToolCommand,
        *,
        trust: ProjectTrust = ProjectTrust.TRUSTED,
    ) -> CheckResult:
        root_path = Path(root).resolve()
        exe = spec.argv[0]
        if exe not in self.ALLOWED_EXECUTABLES:
            return CheckResult(spec.name, spec.category, ReviewStatus.SKIP, list(spec.argv), reason="executable not allowlisted")

        try:
            self._require_execution_authority(root_path, spec)
        except (AuthorizationError, PermissionError) as exc:
            return CheckResult(
                spec.name,
                spec.category,
                ReviewStatus.FAIL,
                list(spec.argv),
                reason=f"capability denied: {exc}",
            )

        policy = SandboxPolicy(trust=trust, timeout_seconds=self.timeout_seconds)
        started = time.perf_counter()

        if trust is ProjectTrust.UNTRUSTED:
            offline_reason = self._offline_dependency_skip(root_path, spec)
            if offline_reason is not None:
                return CheckResult(spec.name, spec.category, ReviewStatus.SKIP, list(spec.argv), reason=offline_reason)
            with tempfile.TemporaryDirectory(prefix="jane-verify-sandbox-") as td:
                try:
                    workspace = self._copy_untrusted_project(root_path, Path(td))
                except OSError as exc:
                    return CheckResult(spec.name, spec.category, ReviewStatus.FAIL, list(spec.argv), reason=f"sandbox copy failed: {exc}")
                container_name = f"jane-verify-{uuid.uuid4().hex[:16]}"
                plan = ContainerSandbox(policy).plan(workspace, spec.argv, container_name=container_name)
                if plan is None:
                    if self.security_event:
                        self.security_event("SandboxExecutionRefused", {"validator": spec.name, "root": str(root_path)})
                    return CheckResult(
                        spec.name,
                        spec.category,
                        ReviewStatus.SKIP,
                        list(spec.argv),
                        reason="untrusted project requires Docker/Podman sandbox with a supported validator image; host fallback is forbidden",
                    )
                scrubbed = ScrubbedEnvironment()
                child_env = scrubbed.build()
                try:
                    completed = subprocess.run(
                        list(plan.argv),
                        cwd=workspace,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout_seconds,
                        shell=False,
                        env=child_env,
                    )
                    status = ReviewStatus.PASS if completed.returncode == 0 else ReviewStatus.FAIL
                    return CheckResult(
                        spec.name,
                        spec.category,
                        status,
                        list(spec.argv),
                        completed.returncode,
                        int((time.perf_counter() - started) * 1000),
                        completed.stdout[-12000:],
                        completed.stderr[-12000:],
                        reason="sandbox=container; network=disabled",
                    )
                except subprocess.TimeoutExpired as exc:
                    if self.security_event:
                        self.security_event("SandboxTimeout", {"validator": spec.name, "root": str(root_path), "container": plan.container_name})
                    cleanup_ok = self._terminate_container(plan.runtime, plan.container_name, child_env)
                    if not cleanup_ok and self.security_event:
                        self.security_event("SandboxContainmentFailure", {"validator": spec.name, "root": str(root_path), "container": plan.container_name})
                    return CheckResult(
                        spec.name,
                        spec.category,
                        ReviewStatus.FAIL,
                        list(spec.argv),
                        None,
                        int((time.perf_counter() - started) * 1000),
                        (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
                        (exc.stderr or "")[-12000:] if isinstance(exc.stderr, str) else "",
                        f"sandboxed command timed out after {self.timeout_seconds}s; container termination {'confirmed' if cleanup_ok else 'NOT confirmed'}",
                    )
                except OSError as exc:
                    return CheckResult(spec.name, spec.category, ReviewStatus.FAIL, list(spec.argv), reason=str(exc))
                finally:
                    scrubbed.close()

        argv, missing_reason = self._resolve_host_argv(root_path, spec)
        if argv is None:
            return CheckResult(spec.name, spec.category, ReviewStatus.SKIP, list(spec.argv), reason=missing_reason or "tool unavailable")

        scrubbed = ScrubbedEnvironment()
        try:
            completed = subprocess.run(
                argv,
                cwd=root_path,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
                env=scrubbed.build(),
            )
            status = ReviewStatus.PASS if completed.returncode == 0 else ReviewStatus.FAIL
            return CheckResult(
                spec.name,
                spec.category,
                status,
                list(spec.argv),
                completed.returncode,
                int((time.perf_counter()-started)*1000),
                completed.stdout[-12000:],
                completed.stderr[-12000:],
                reason="trusted-project host execution; environment scrubbed",
            )
        except subprocess.TimeoutExpired as exc:
            return CheckResult(
                spec.name,
                spec.category,
                ReviewStatus.FAIL,
                list(spec.argv),
                None,
                int((time.perf_counter()-started)*1000),
                (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
                (exc.stderr or "")[-12000:] if isinstance(exc.stderr, str) else "",
                f"timed out after {self.timeout_seconds}s",
            )
        except OSError as exc:
            return CheckResult(spec.name, spec.category, ReviewStatus.FAIL, list(spec.argv), reason=str(exc))
        finally:
            scrubbed.close()
