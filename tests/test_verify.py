from pathlib import Path
from janeos.kernel.runtime import JaneOS
from janeos.kernel.capabilities import CapabilityRequest
from jane_verify import JaneVerify
from jane_verify.manifest import VERIFY_MANIFEST

def test_registers_as_janeos_application(tmp_path):
    osys=JaneOS(); JaneVerify(osys,data_dir=tmp_path/'data')
    assert osys.applications_providing('software.validate')[0]['app_id']=='jane.verify'

def test_authorization_is_project_scoped(tmp_path):
    project=tmp_path/'p'; project.mkdir(); (project/'hello.py').write_text('print("ok")')
    osys=JaneOS(); verify=JaneVerify(osys,data_dir=tmp_path/'data'); verify.authorize_project(project)
    d=osys.authorize(CapabilityRequest(capability='review.project.read',provider_id='jane.verify',resource=f'project:{project.resolve().as_posix()}/hello.py',actor='jane.verify'))
    assert d.allowed
    other=tmp_path/'other'; other.mkdir()
    d2=osys.authorize(CapabilityRequest(capability='review.project.read',provider_id='jane.verify',resource=f'project:{other.resolve().as_posix()}/secret',actor='jane.verify'))
    assert not d2.allowed

def test_python_project_validates_and_generates_docs(tmp_path):
    project=tmp_path/'p'; project.mkdir(); (project/'pyproject.toml').write_text('[project]\nname="x"\nversion="0.1"\n'); (project/'hello.py').write_text('x=1\n')
    osys=JaneOS(); verify=JaneVerify(osys,data_dir=tmp_path/'data'); verify.authorize_project(project)
    result=verify.validate(project)
    assert result['validation']['stack']['languages']==['Python']
    assert Path(result['artifacts']['documentation']).exists()
    assert Path(result['artifacts']['report']).exists()

def test_manifest_has_no_wildcards():
    assert all('*' not in x for x in VERIFY_MANIFEST.provides+VERIFY_MANIFEST.requires)
