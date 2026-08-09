from pathlib import Path
from datetime import datetime, timezone

def render_markdown(bundle: dict) -> str:
    r=bundle["validation"]
    lines=["# Jane Verify Report","",f"Project: `{bundle['project']}`",f"Generated: {datetime.now(timezone.utc).isoformat()}","",f"## Result: {r['status'].upper()} — {r['score']}/100","",
           f"Passed: {r['summary']['passed']}  |  Failed: {r['summary']['failed']}  |  Skipped: {r['summary']['skipped']}","","## Checks",""]
    for c in r['checks']:
        lines.append(f"- **{c['status'].upper()}** {c['name']} — {c['category']}" + (f" — {c['reason']}" if c.get('reason') else ""))
    findings=bundle.get('findings',[])
    lines += ["", "## Findings",""]
    if not findings: lines.append("No heuristic code/security findings.")
    else:
        for f in findings: lines.append(f"- **{f['severity'].upper()}** `{f['file']}:{f['line']}` — {f['message']}")
    return "\n".join(lines)+"\n"

def write_markdown(output_dir: str|Path, content: str, filename: str='VALIDATION_REPORT.md') -> Path:
    out=Path(output_dir).expanduser().resolve(); out.mkdir(parents=True, exist_ok=True); p=out/filename; p.write_text(content, encoding='utf-8'); return p
