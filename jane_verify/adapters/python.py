from pathlib import Path
from .base import ReviewAdapter
from jane_verify.models import ToolCommand, StackProfile

class PythonAdapter(ReviewAdapter):
    def supports(self, stack: StackProfile) -> bool: return "Python" in stack.languages
    def commands(self, root: Path, stack: StackProfile) -> list[ToolCommand]:
        cmds=[ToolCommand("Python compile", ("python","-m","compileall","-q","."), "syntax", optional=False)]
        if (root/"tests").exists(): cmds.append(ToolCommand("pytest", ("python","-m","pytest","-q"), "tests", optional=False))
        if (root/"ruff.toml").exists() or (root/"pyproject.toml").exists(): cmds.append(ToolCommand("Ruff", ("ruff","check","."), "static-analysis"))
        if (root/"mypy.ini").exists(): cmds.append(ToolCommand("mypy", ("mypy","."), "static-analysis"))
        return cmds
