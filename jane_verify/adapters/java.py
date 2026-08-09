from pathlib import Path
from .base import ReviewAdapter
from jane_verify.models import ToolCommand, StackProfile

class JavaAdapter(ReviewAdapter):
    def supports(self, stack: StackProfile) -> bool: return "Java" in stack.languages
    def commands(self, root: Path, stack: StackProfile) -> list[ToolCommand]:
        if (root/"mvnw").exists(): return [ToolCommand("Maven tests", ("mvn","test","-q"), "tests", optional=False)]
        if (root/"pom.xml").exists(): return [ToolCommand("Maven tests", ("mvn","test","-q"), "tests", optional=False)]
        if (root/"gradlew").exists(): return [ToolCommand("Gradle tests", ("gradlew","test"), "tests", optional=False)]
        if (root/"build.gradle").exists() or (root/"build.gradle.kts").exists(): return [ToolCommand("Gradle tests", ("gradle","test"), "tests", optional=False)]
        return []
