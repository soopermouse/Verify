import json
from pathlib import Path
from .base import ReviewAdapter
from jane_verify.models import ToolCommand, StackProfile

class NodeAdapter(ReviewAdapter):
    def supports(self, stack: StackProfile) -> bool: return "JavaScript" in stack.languages or "TypeScript" in stack.languages
    def commands(self, root: Path, stack: StackProfile) -> list[ToolCommand]:
        cmds=[]
        try: scripts=json.loads((root/"package.json").read_text(encoding="utf-8")).get("scripts",{})
        except Exception: scripts={}
        for script,cat in (("lint","static-analysis"),("typecheck","static-analysis"),("test","tests"),("build","build")):
            if script in scripts: cmds.append(ToolCommand(f"npm {script}", ("npm","run",script,"--if-present"), cat, optional=script!="test"))
        if "TypeScript" in stack.languages and (root/"tsconfig.json").exists() and "typecheck" not in scripts:
            cmds.append(ToolCommand("TypeScript compile", ("npx","--no-install","tsc","--noEmit"), "static-analysis"))
        return cmds
