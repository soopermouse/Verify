from janeos.apps import ApplicationManifest

VERIFY_MANIFEST = ApplicationManifest(
    app_id="jane.verify",
    name="Jane Verify",
    version="1.0.0",
    description="Software validation, testing, inspection and documentation product running on JaneOS capabilities.",
    provides=(
        "software.validate",
        "stack.detect",
        "tests.run",
        "code.inspect",
        "security.inspect",
        "documentation.generate",
        "report.generate",
    ),
    requires=(
        "review.project.read",
        "review.validator.execute",
    ),
    entrypoint="jane_verify.app:JaneVerify",
    metadata={
        "product": True,
        "managed_by": "jane",
        "ui": "/",
        "api": "/api",
    },
)
