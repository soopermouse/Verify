from __future__ import annotations
from pathlib import Path
from janeos.kernel.capabilities import CapabilityGrant, CapabilityManifest, CapabilityRequest, CapabilitySpec, Effect
from janeos.kernel.authorization import AuthorizationError
from jane_verify.models import ReviewReport, ReviewStatus
from jane_verify.execution import SafeCommandRunner, ProjectTrust
from jane_verify.stack_detector import StackDetector
from jane_verify.adapters.php import PhpAdapter
from jane_verify.adapters.node import NodeAdapter
from jane_verify.adapters.python import PythonAdapter
from jane_verify.adapters.java import JavaAdapter
from jane_verify.adapters.dotnet import DotNetAdapter

class ValidationOrchestrator:
    PROVIDER_ID='jane.verify'
    READ='review.project.read'
    EXEC='review.validator.execute'
    ACTOR='jane.verify'

    def __init__(self, osys, timeout_seconds: int=120):
        self.os=osys; self.authorization=osys.authorization; self.detector=StackDetector()
        self.adapters=[PhpAdapter(),NodeAdapter(),PythonAdapter(),JavaAdapter(),DotNetAdapter()]
        self.runner=SafeCommandRunner(timeout_seconds, authorization=self.authorization, actor=self.ACTOR, security_event=self._event)
        self._ensure_manifest()

    def _event(self, event_type, payload):
        self.os.publish(event_type,'jane.verify.sandbox',payload,priority=9)

    @staticmethod
    def _root(root): return Path(root).expanduser().resolve()
    @classmethod
    def _read_resource(cls,root): return f"project:{root.as_posix()}/**"
    @classmethod
    def _exec_resource(cls,root): return f"project:{root.as_posix()}"

    def _ensure_manifest(self):
        m=self.authorization.capabilities.manifest(self.PROVIDER_ID)
        if m: return m
        m=CapabilityManifest(provider_id=self.PROVIDER_ID, api_backed=True, description='Jane Verify validation provider', capabilities={
            self.READ: CapabilitySpec(self.READ,Effect.READ,description='Read an explicitly authorized software project'),
            self.EXEC: CapabilitySpec(self.EXEC,Effect.EXECUTE,description='Execute deterministic validators for an authorized project'),
        })
        self.os.register_capability_provider(m); return m

    def authorize_project(self, root):
        root=self._root(root)
        if not root.is_dir(): raise ValueError('project root must be an existing directory')
        m=self._ensure_manifest(); desired=[CapabilityGrant(self.READ,(self._read_resource(root),)),CapabilityGrant(self.EXEC,(self._exec_resource(root),))]
        existing={(g.capability,g.resources) for g in m.grants}
        for g in desired:
            if (g.capability,g.resources) not in existing: m.grants.append(g)
        # Jane deliberately delegates only the exact scopes currently granted to Verify.
        delegated = [g for g in m.grants if g.capability in {self.READ, self.EXEC}]
        self.os.delegate_capabilities(parent_actor='jane', child_actor=self.ACTOR, grants={self.PROVIDER_ID: delegated})
        self.os.publish('VerifyProjectAuthorized','jane.verify',{'root':str(root)},priority=7)
        return {'root':str(root),'read_scope':self._read_resource(root),'execute_scope':self._exec_resource(root)}

    def revoke_project(self, root):
        root=self._root(root); m=self._ensure_manifest(); rs=self._read_resource(root); es=self._exec_resource(root)
        m.grants[:]=[g for g in m.grants if not ((g.capability==self.READ and rs in g.resources) or (g.capability==self.EXEC and es in g.resources))]
        self.os.revoke_delegated_actor(self.ACTOR)
        self.os.publish('VerifyProjectRevoked','jane.verify',{'root':str(root)},priority=7)

    def _require_read(self,root):
        self.authorization.require(CapabilityRequest(capability=self.READ,provider_id=self.PROVIDER_ID,resource=self._read_resource(root),actor=self.ACTOR,purpose='stack detection and source inspection'))

    def validate(self, root, trust: ProjectTrust|str=ProjectTrust.TRUSTED) -> ReviewReport:
        root=self._root(root)
        if not root.is_dir(): raise ValueError('project root must be an existing directory')
        trust=trust if isinstance(trust,ProjectTrust) else ProjectTrust(trust)
        self._require_read(root); stack=self.detector.detect(root); checks=[]
        for a in self.adapters:
            if a.supports(stack):
                for cmd in a.commands(root,stack): checks.append(self.runner.run(root,cmd,trust=trust))
        passed=sum(c.status==ReviewStatus.PASS for c in checks); failed=sum(c.status==ReviewStatus.FAIL for c in checks); skipped=sum(c.status==ReviewStatus.SKIP for c in checks)
        status=ReviewStatus.FAIL if failed else (ReviewStatus.WARN if skipped else ReviewStatus.PASS)
        executable=max(1,passed+failed); score=max(0,round(100*(passed/executable)-min(20,skipped*2)))
        report=ReviewReport(str(root),stack,trust.value,checks,status,score,passed,skipped,failed,skipped)
        self.os.publish('SoftwareValidationCompleted','jane.verify',{'root':str(root),'status':status.value,'score':score,'failed':failed,'skipped':skipped},priority=7 if failed else 5)
        return report
