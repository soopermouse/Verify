from pathlib import Path
from .base import ReviewAdapter
from jane_verify.models import ToolCommand, StackProfile

class DotNetAdapter(ReviewAdapter):
    def supports(self, stack: StackProfile) -> bool: return ".NET" in stack.languages
    def commands(self, root: Path, stack: StackProfile) -> list[ToolCommand]:
        return [ToolCommand("dotnet test", ("dotnet","test","--nologo"), "tests", optional=False)]
