from __future__ import annotations
from pathlib import Path
from jane_verify.manifest import VERIFY_MANIFEST
from jane_verify.orchestrator import ValidationOrchestrator
from jane_verify.inspection import CodeInspector
from jane_verify.documentation import DocumentationGenerator
from jane_verify.reporting import render_markdown, write_markdown

class JaneVerify:
    """Standalone JaneOS application managed by Jane."""
    def __init__(self, osys, *, data_dir: str|Path|None=None, timeout_seconds: int=120):
        self.os=osys
        self.data_dir=Path(data_dir or Path.home()/'.jane'/'verify').expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.validator=ValidationOrchestrator(osys,timeout_seconds)
        self.inspector=CodeInspector(); self.docs=DocumentationGenerator()
        self.os.register_application(VERIFY_MANIFEST)

    def authorize_project(self, root): return self.validator.authorize_project(root)
    def revoke_project(self, root): return self.validator.revoke_project(root)

    def validate(self, root, *, trust='trusted') -> dict:
        report=self.validator.validate(root,trust=trust); findings=[f.to_dict() for f in self.inspector.scan(root)]
        bundle={'project':str(Path(root).resolve()),'validation':report.to_dict(),'findings':findings}
        project_dir=self.data_dir/'projects'/Path(root).resolve().name
        project_dir.mkdir(parents=True,exist_ok=True)
        report_path=write_markdown(project_dir,render_markdown(bundle))
        docs=self.docs.generate(root,report.stack,report,findings)
        docs_path=self.docs.write(project_dir,docs)
        bundle['artifacts']={'report':str(report_path),'documentation':str(docs_path)}
        self.os.publish('VerifyArtifactsGenerated','jane.verify',bundle['artifacts'],priority=5)
        return bundle

    def generate_documentation(self, root) -> dict:
        root=Path(root).resolve(); self.validator._require_read(root)
        stack=self.validator.detector.detect(root); findings=[f.to_dict() for f in self.inspector.scan(root)]
        content=self.docs.generate(root,stack,None,findings)
        project_dir=self.data_dir/'projects'/root.name; path=self.docs.write(project_dir,content)
        self.os.publish('DocumentationGenerated','jane.verify',{'root':str(root),'path':str(path)},priority=5)
        return {'root':str(root),'path':str(path),'content':content}

    def capabilities(self): return VERIFY_MANIFEST.to_dict()
