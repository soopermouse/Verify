from __future__ import annotations
from pathlib import Path
from jane_verify.models import ToolCommand, StackProfile


class ReviewAdapter:
    def supports(self, stack: StackProfile) -> bool:
        return False

    def commands(self, root: Path, stack: StackProfile) -> list[ToolCommand]:
        return []
