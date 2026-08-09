from __future__ import annotations
import os
from janeos.kernel.runtime import JaneOS
from jane_verify.app import JaneVerify
from jane_verify.ui import render_dashboard

def create_app(osys=None, verify=None):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse
        from pydantic import BaseModel
    except ImportError as exc:
        raise RuntimeError("Install Jane Verify with [api] extra") from exc
    osys=osys or JaneOS(); verify=verify or JaneVerify(osys)
    app=FastAPI(title="Jane Verify",version="1.0.0")
    class ProjectRequest(BaseModel): root:str
    class ValidateRequest(BaseModel): root:str; trust:str="trusted"
    @app.get("/",response_class=HTMLResponse)
    def dashboard(): return render_dashboard()
    @app.get("/api/manifest")
    def manifest(): return verify.capabilities()
    @app.get("/api/apps")
    def apps(): return osys.list_applications()
    @app.post("/api/projects/authorize")
    def authorize(req:ProjectRequest):
        try: return verify.authorize_project(req.root)
        except Exception as exc: raise HTTPException(400,str(exc))
    @app.post("/api/projects/revoke")
    def revoke(req:ProjectRequest):
        verify.revoke_project(req.root); return {"status":"revoked"}
    @app.post("/api/validate")
    def validate(req:ValidateRequest):
        try: return verify.validate(req.root,trust=req.trust)
        except PermissionError as exc: raise HTTPException(403,str(exc))
        except Exception as exc: raise HTTPException(400,str(exc))
    @app.post("/api/documentation")
    def documentation(req:ProjectRequest):
        try: return verify.generate_documentation(req.root)
        except PermissionError as exc: raise HTTPException(403,str(exc))
        except Exception as exc: raise HTTPException(400,str(exc))
    @app.get("/api/security/capabilities")
    def capabilities(): return osys.authorization.snapshot()
    return app

def main():
    try: import uvicorn
    except ImportError as exc: raise RuntimeError("Install Jane Verify with [api] extra") from exc
    uvicorn.run(create_app(),host=os.getenv("JANE_VERIFY_HOST","127.0.0.1"),port=int(os.getenv("JANE_VERIFY_PORT","8010")))
