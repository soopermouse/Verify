from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import re

SOURCE_EXTS={".py",".php",".js",".jsx",".ts",".tsx",".java",".cs",".go",".rs",".vue"}
SKIP_DIRS={".git","node_modules","vendor","dist","build","target",".venv","venv","__pycache__"}

@dataclass
class Finding:
    severity: str
    category: str
    file: str
    line: int
    message: str
    evidence: str = ""
    def to_dict(self): return asdict(self)

class CodeInspector:
    """Read-only heuristic inspection. Findings are evidence, not proof."""
    PATTERNS=(
        ("high","security",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),"Private key material appears in source"),
        ("high","security",re.compile(r"AKIA[0-9A-Z]{16}"),"Possible AWS access key in source"),
        ("medium","security",re.compile(r"(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),"Possible hard-coded credential or secret"),
        ("medium","security",re.compile(r"\beval\s*\("),"Dynamic eval detected; review input trust boundary"),
        ("low","quality",re.compile(r"\b(TODO|FIXME|HACK)\b"),"Outstanding implementation marker"),
        ("medium","quality",re.compile(r"except\s+Exception\s*:\s*(?:pass)?$"),"Broad exception handling may hide failures"),
    )
    def scan(self, root: str|Path, limit: int=500) -> list[Finding]:
        root=Path(root).resolve(); findings=[]
        for path in root.rglob('*'):
            if len(findings)>=limit: break
            if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS: continue
            if any(part in SKIP_DIRS for part in path.relative_to(root).parts): continue
            try: lines=path.read_text(encoding='utf-8', errors='ignore').splitlines()
            except OSError: continue
            for n,line in enumerate(lines,1):
                for sev,cat,pattern,msg in self.PATTERNS:
                    if pattern.search(line):
                        evidence=line.strip()[:240]
                        findings.append(Finding(sev,cat,str(path.relative_to(root)),n,msg,evidence))
        return findings
