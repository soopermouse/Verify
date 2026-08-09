from __future__ import annotations
import argparse, json
from janeos.kernel.runtime import JaneOS
from jane_verify.app import JaneVerify

def main():
    p=argparse.ArgumentParser(prog="jane-verify",description="Jane Verify — software validation on JaneOS")
    p.add_argument("project",nargs="?"); p.add_argument("--trust",choices=["trusted","untrusted"],default="trusted"); p.add_argument("--docs",action="store_true"); p.add_argument("--serve",action="store_true"); p.add_argument("--data-dir")
    a=p.parse_args()
    if a.serve:
        from jane_verify.api import main as serve; return serve()
    if not a.project: p.error("project path is required unless --serve is used")
    osys=JaneOS(); verify=JaneVerify(osys,data_dir=a.data_dir); verify.authorize_project(a.project)
    result=verify.generate_documentation(a.project) if a.docs else verify.validate(a.project,trust=a.trust)
    print(json.dumps(result,indent=2))
if __name__=="__main__": main()
