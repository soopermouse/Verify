from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import shutil
import tempfile
from typing import Iterable


class ProjectTrust(str, Enum):
    """How much Jane trusts code in the project being reviewed."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class SandboxPolicy:
    """Execution isolation policy for Jane Verify.

    Untrusted projects MUST run in a container with networking disabled. Jane
    Verify deliberately refuses to fall back to host execution for untrusted
    code when a container runtime is unavailable.
    """

    trust: ProjectTrust = ProjectTrust.TRUSTED
    network: bool = False
    memory_mb: int = 4096
    cpu_count: float = 2.0
    pids_limit: int = 256
    timeout_seconds: int = 120


class ScrubbedEnvironment:
    """Build a minimal child-process environment with no Jane/user secrets.

    Only operating-system/tool-discovery variables are inherited. HOME-style
    locations are replaced with an ephemeral directory controlled by Jane
    Verify. API keys, cloud tokens, SSH variables and arbitrary parent env vars
    are intentionally absent.
    """

    SAFE_INHERITED_KEYS = (
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    )

    def __init__(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="jane-verify-env-")
        home = Path(self._temp.name).resolve()
        (home / "tmp").mkdir(parents=True, exist_ok=True)
        (home / "cache").mkdir(parents=True, exist_ok=True)
        self.home = home

    def build(self) -> dict[str, str]:
        env = {key: os.environ[key] for key in self.SAFE_INHERITED_KEYS if key in os.environ}
        env.update(
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "APPDATA": str(self.home / "cache"),
                "LOCALAPPDATA": str(self.home / "cache"),
                "TMP": str(self.home / "tmp"),
                "TEMP": str(self.home / "tmp"),
                "TMPDIR": str(self.home / "tmp"),
                "XDG_CACHE_HOME": str(self.home / "cache"),
                "CI": "1",
                "NO_COLOR": "1",
                # Prevent common tooling from prompting or collecting telemetry.
                "GIT_TERMINAL_PROMPT": "0",
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                "DOTNET_NOLOGO": "1",
                "NPM_CONFIG_FUND": "false",
                "NPM_CONFIG_AUDIT": "false",
                "COMPOSER_NO_INTERACTION": "1",
            }
        )
        return env

    def close(self) -> None:
        self._temp.cleanup()


@dataclass(frozen=True)
class ContainerPlan:
    runtime: str
    image: str
    argv: tuple[str, ...]
    container_name: str


class ContainerSandbox:
    """Construct a hardened container command for untrusted repository code."""

    IMAGE_BY_EXECUTABLE = {
        "python": "python:3.13-slim",
        "python3": "python:3.13-slim",
        "pytest": "python:3.13-slim",
        "ruff": "python:3.13-slim",
        "mypy": "python:3.13-slim",
        "bandit": "python:3.13-slim",
        "node": "node:22-bookworm-slim",
        "npm": "node:22-bookworm-slim",
        "npx": "node:22-bookworm-slim",
        "php": "php:8.3-cli",
        "composer": "composer:2",
        "vendor/bin/phpunit": "php:8.3-cli",
        "vendor/bin/phpstan": "php:8.3-cli",
        "vendor/bin/psalm": "php:8.3-cli",
        "bin/console": "php:8.3-cli",
        "mvn": "maven:3.9-eclipse-temurin-21",
        "gradle": "gradle:8-jdk21",
        "gradlew": "gradle:8-jdk21",
        "dotnet": "mcr.microsoft.com/dotnet/sdk:9.0",
    }

    def __init__(self, policy: SandboxPolicy) -> None:
        self.policy = policy

    @staticmethod
    def available_runtime() -> str | None:
        for candidate in ("docker", "podman"):
            if shutil.which(candidate):
                return candidate
        return None

    def plan(self, root: Path, original_argv: Iterable[str], *, container_name: str) -> ContainerPlan | None:
        original = tuple(original_argv)
        if not original:
            return None
        runtime = self.available_runtime()
        if runtime is None:
            return None
        image = self.IMAGE_BY_EXECUTABLE.get(original[0])
        if image is None:
            return None

        # Mount the repository read/write only inside the container namespace.
        # The host repository itself is protected by first copying it to a temp
        # workspace in SafeCommandRunner before this plan is executed.
        argv = [
            runtime,
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "bridge" if self.policy.network else "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.policy.pids_limit),
            "--memory",
            f"{self.policy.memory_mb}m",
            "--cpus",
            str(self.policy.cpu_count),
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=512m",
            "-e",
            "HOME=/tmp/jane-home",
            "-e",
            "TMPDIR=/tmp",
            "-e",
            "CI=1",
            "-e",
            "NO_COLOR=1",
            "-v",
            f"{root}:/workspace:rw",
            "-w",
            "/workspace",
            image,
            *original,
        ]
        return ContainerPlan(runtime=runtime, image=image, argv=tuple(argv), container_name=container_name)
