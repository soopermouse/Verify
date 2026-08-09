from __future__ import annotations
import json
from pathlib import Path
from .models import StackProfile


class StackDetector:
    """Detect project language/framework from trusted project files, without execution."""

    def detect(self, root: str | Path) -> StackProfile:
        path = Path(root).expanduser().resolve()
        languages: set[str] = set()
        frameworks: set[str] = set()
        manifests: list[str] = []
        tests: set[str] = set()

        def has(name: str) -> bool:
            return (path / name).exists()

        if has("composer.json"):
            languages.add("PHP"); manifests.append("composer.json")
            try:
                composer = json.loads((path / "composer.json").read_text(encoding="utf-8"))
                req = {**composer.get("require", {}), **composer.get("require-dev", {})}
                if any(k.startswith("symfony/") for k in req): frameworks.add("Symfony")
                if "laravel/framework" in req: frameworks.add("Laravel")
                if "phpunit/phpunit" in req: tests.add("PHPUnit")
            except Exception:
                pass
        if has("package.json"):
            languages.update(["JavaScript", "TypeScript"]); manifests.append("package.json")
            try:
                package = json.loads((path / "package.json").read_text(encoding="utf-8"))
                deps = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
                if "next" in deps: frameworks.add("Next.js")
                if "@angular/core" in deps: frameworks.add("Angular")
                if "vue" in deps: frameworks.add("Vue")
                if "react" in deps: frameworks.add("React")
                if "vitest" in deps: tests.add("Vitest")
                if "jest" in deps: tests.add("Jest")
                if "@playwright/test" in deps: tests.add("Playwright")
            except Exception:
                pass
        if has("pyproject.toml") or has("requirements.txt"):
            languages.add("Python")
            manifests.extend([n for n in ("pyproject.toml", "requirements.txt") if has(n)])
            if has("pytest.ini") or has("tests") or has("pyproject.toml"): tests.add("pytest")
            if has("manage.py"): frameworks.add("Django")
        if has("pom.xml") or has("build.gradle") or has("build.gradle.kts"):
            languages.add("Java")
            manifests.extend([n for n in ("pom.xml", "build.gradle", "build.gradle.kts") if has(n)])
            tests.add("JUnit")
            if has("pom.xml"):
                try:
                    text=(path/"pom.xml").read_text(encoding="utf-8", errors="ignore")
                    if "spring-boot" in text: frameworks.add("Spring Boot")
                except Exception: pass
        if list(path.glob("*.sln")) or list(path.glob("*.csproj")):
            languages.add(".NET")
            manifests.extend([p.name for p in list(path.glob("*.sln"))[:2] + list(path.glob("*.csproj"))[:2]])
            tests.add("dotnet test")

        return StackProfile(
            root=str(path),
            languages=sorted(languages),
            frameworks=sorted(frameworks),
            manifests=manifests,
            test_frameworks=sorted(tests),
        )
