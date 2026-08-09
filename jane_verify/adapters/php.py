from pathlib import Path
from .base import ReviewAdapter
from jane_verify.models import ToolCommand, StackProfile

class PhpAdapter(ReviewAdapter):
    def supports(self, stack: StackProfile) -> bool: return "PHP" in stack.languages
    def commands(self, root: Path, stack: StackProfile) -> list[ToolCommand]:
        cmds=[ToolCommand("Composer validate", ("composer","validate","--no-interaction","--no-plugins"), "dependencies")]
        if (root/"vendor/bin/phpunit").exists(): cmds.append(ToolCommand("PHPUnit", ("vendor/bin/phpunit",), "tests", optional=False))
        if (root/"vendor/bin/phpstan").exists(): cmds.append(ToolCommand("PHPStan", ("vendor/bin/phpstan","analyse","--no-progress"), "static-analysis"))
        if (root/"vendor/bin/psalm").exists(): cmds.append(ToolCommand("Psalm", ("vendor/bin/psalm","--no-progress"), "static-analysis"))
        if "Symfony" in stack.frameworks and (root/"bin/console").exists():
            cmds.extend([
                ToolCommand("Symfony container", ("php","bin/console","lint:container"), "framework"),
                ToolCommand("Symfony YAML", ("php","bin/console","lint:yaml","config"), "framework"),
                ToolCommand("Symfony Twig", ("php","bin/console","lint:twig","templates"), "framework"),
            ])
        return cmds
