"""Execute source methods with real Flask/JWT/RBAC and inert assessment doubles."""

import ast
from datetime import datetime, timedelta, timezone
import logging
import os
from pathlib import Path
import ssl
import types
import unittest
from unittest.mock import Mock, MagicMock, patch
import uuid

import flask
import jwt
from security.authentication import EnterpriseAuth, RoleBasedAccessControl

ROOT = Path(__file__).resolve().parents[2]
PHASES = (
    "phase1_reconnaissance",
    "phase2_scanning_enumeration",
    "phase3_vulnerability_assessment",
    "phase4_exploitation",
    "phase5_reporting",
    "phase6_retesting",
)


def source_methods():
    """Load real method bodies without initializing services or executing phases."""
    tree = ast.parse((ROOT / "hackgpt_v2.py").read_text(encoding="utf-8"))
    owner = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "EnterpriseHackGPT"
    )
    names = {"create_api_app", "start_api_server", "run_full_enterprise_pentest"}
    methods = [
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert len(methods) == len(names)
    wrapper = ast.ClassDef(
        name="SourceMethods", bases=[], keywords=[], body=methods, decorator_list=[]
    )
    namespace = {
        "__name__": __name__,
        "flask": flask,
        "config": types.SimpleNamespace(SECRET_KEY="synthetic-flask-secret"),
        "datetime": datetime,
        "os": os,
        "uuid": uuid,
        "threading": types.SimpleNamespace(Thread=Mock()),
        "EnterprisePentestingPhases": Mock(),
        "Progress": MagicMock(),
        "SpinnerColumn": Mock(),
        "TextColumn": Mock(),
        "BarColumn": Mock(),
    }
    module = ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[]))
    exec(compile(module, str(ROOT / "hackgpt_v2.py"), "exec"), namespace)
    return namespace["SourceMethods"], namespace


class ReviewRuntimeTests(unittest.TestCase):
    """Observe route denial and terminal-state behavior without external targets."""

    def setUp(self):
        """Construct the real API routes with a test-only JWT secret."""
        cls, self.namespace = source_methods()
        self.owner = cls()
        self.owner.console = Mock()
        self.owner.logger = Mock()
        self.owner.auth = EnterpriseAuth.__new__(EnterpriseAuth)
        self.owner.auth.rbac = RoleBasedAccessControl()
        self.owner.auth.authenticate_user = Mock(
            return_value=types.SimpleNamespace(
                success=True,
                token="synthetic-response-token",
                user_id="verified-user",
                username="fixture",
                role="senior_analyst",
                permissions=[],
            )
        )
        self.secret = "synthetic-test-secret-" + uuid.uuid4().hex
        env = patch.dict(os.environ, {"JWT_SECRET_KEY": self.secret})
        env.start()
        self.addCleanup(env.stop)
        self.owner.db = Mock()
        self.owner.db.create_pentest_session.return_value = "synthetic-session"
        self.owner.db.get_recent_sessions.return_value = []
        for field in (
            "ai_engine",
            "tool_manager",
            "cache",
            "processor",
            "exploitation",
            "zero_day_detector",
            "compliance",
            "report_generator",
            "show_pentest_summary",
        ):
            setattr(self.owner, field, Mock())
        phases = Mock(results={})
        for name in PHASES:
            setattr(phases, name, Mock(return_value={"success": True}))
        self.namespace["EnterprisePentestingPhases"].return_value = phases
        self.phases = phases
        self.app = self.owner.create_api_app()
        self.client = self.app.test_client()

    def token(self, role="senior_analyst"):
        """Mint only a synthetic local JWT for the real verification decorator."""
        return jwt.encode(
            {
                "user_id": "verified-user",
                "username": "fixture",
                "role": role,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=2),
            },
            self.secret,
            algorithm="HS256",
        )

    def request(self, path, data=None, role="senior_analyst"):
        """Submit HTTPS-scheme WSGI requests without a network connection."""
        return self.client.post(
            path,
            json=data,
            base_url="https://localhost",
            headers={"Authorization": "Bearer " + self.token(role)},
        )

    def test_cleartext_login_never_authenticates(self):
        """Cleartext is denied before credentials reach the authentication object."""
        response = self.client.post(
            "/api/auth/login",
            json={"username": "fixture", "password": "synthetic-password"},
        )
        self.assertEqual(response.status_code, 400)
        self.owner.auth.authenticate_user.assert_not_called()

    def test_forwarded_header_cannot_spoof_https(self):
        """An untrusted forwarded-proto header must not bypass transport checks."""
        response = self.client.post(
            "/api/auth/login",
            headers={"X-Forwarded-Proto": "https"},
            json={"username": "fixture", "password": "synthetic-password"},
        )
        self.assertEqual(response.status_code, 400)
        self.owner.auth.authenticate_user.assert_not_called()

    def test_owned_loopback_tls_handshake_and_cleartext_rejection(self):
        """Verify trusted TLS end-to-end using a disposable localhost certificate."""
        import http.client
        import shutil
        import subprocess
        import tempfile
        import threading
        from werkzeug.serving import make_server

        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("OpenSSL is required for the owned-loopback TLS fixture")
        with tempfile.TemporaryDirectory(prefix="hackgpt-tls-fixture-") as directory:
            cert = Path(directory) / "fixture.crt"
            key = Path(directory) / "fixture.key"
            subprocess.run(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                ],
                check=True,
                capture_output=True,
                timeout=20,
            )
            key.chmod(0o600)
            server = make_server(
                "127.0.0.1", 0, self.app, ssl_context=(str(cert), str(key))
            )
            server.timeout = 2
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                plaintext = http.client.HTTPConnection(
                    "127.0.0.1", server.server_port, timeout=3
                )
                try:
                    plaintext.request(
                        "POST",
                        "/api/auth/login",
                        body="{}",
                        headers={"Content-Type": "application/json"},
                    )
                    response = plaintext.getresponse()
                    self.assertGreaterEqual(response.status, 400)
                except (OSError, http.client.HTTPException):
                    pass  # A TLS listener can close a non-TLS connection before HTTP.
                finally:
                    plaintext.close()
                self.owner.auth.authenticate_user.assert_not_called()

                trusted = ssl.create_default_context(cafile=str(cert))
                connection = http.client.HTTPSConnection(
                    "127.0.0.1", server.server_port, context=trusted, timeout=3
                )
                try:
                    import json

                    connection.request(
                        "POST",
                        "/api/auth/login",
                        body=json.dumps(
                            {"username": "fixture", "password": "synthetic-password"}
                        ),
                        headers={"Content-Type": "application/json"},
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(
                        json.loads(response.read())["token"], "synthetic-response-token"
                    )
                finally:
                    connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

    def test_https_login_uses_real_flask_json_parsing(self):
        """The HTTPS route remains usable with an authentication service."""
        response = self.request(
            "/api/auth/login", {"username": "fixture", "password": "synthetic-password"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["token"], "synthetic-response-token")

    def test_start_requires_token_and_all_phase_permissions(self):
        """Session creation alone must not permit all six assessment phases."""
        response = self.client.post(
            "/api/pentest/start", base_url="https://localhost", json={}
        )
        self.assertEqual(response.status_code, 401)
        for role in ("viewer", "analyst"):
            with self.subTest(role=role):
                self.assertEqual(
                    self.request("/api/pentest/start", {}, role=role).status_code, 403
                )
        self.namespace["threading"].Thread.assert_not_called()

    def test_verified_creator_replaces_body_identity(self):
        """Bind a valid request to its JWT subject, never a caller-supplied owner."""
        response = self.request(
            "/api/pentest/start",
            {
                "target": "fixture.invalid",
                "scope": "offline fixture",
                "auth_key": "synthetic-reference",
                "created_by": "spoofed-user",
            },
        )
        self.assertEqual(response.status_code, 200)
        captured = self.namespace["threading"].Thread.call_args.kwargs["args"][0]
        self.assertEqual(captured["created_by"], "verified-user")
        self.namespace["EnterprisePentestingPhases"].assert_not_called()

    def test_sessions_serialize_the_real_database_model(self):
        """A populated real SQLite session must serialize its actual model ID."""
        from database.manager import DatabaseManager

        database = DatabaseManager("sqlite:///:memory:")
        self.addCleanup(database.engine.dispose)
        self.assertTrue(database.create_tables())
        self.owner.db = database
        session_id = database.create_pentest_session(
            target="fixture.invalid",
            scope="offline fixture",
            created_by="verified-user",
            auth_key="synthetic-reference",
        )
        response = self.client.get(
            "/api/sessions",
            base_url="https://localhost",
            headers={"Authorization": "Bearer " + self.token()},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()[0]["session_id"], session_id)
        self.assertEqual(response.get_json()[0]["target"], "fixture.invalid")

    def test_json_arrays_do_not_crash_handlers(self):
        """Reject JSON arrays with a client error rather than a server exception."""
        for path in ("/api/auth/login", "/api/pentest/start"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path, ["invalid"]).status_code, 400)

    def test_unconfigured_tls_never_opens_listener(self):
        """Missing TLS material must fail before server construction."""
        with patch.dict(
            os.environ, {"HACKGPT_API_TLS_CERT": "", "HACKGPT_API_TLS_KEY": ""}
        ), patch.object(self.owner, "create_api_app") as create:
            self.assertIs(self.owner.start_api_server(), False)
            create.assert_not_called()

    def test_tls_startup_disables_debug_and_defaults_loopback(self):
        """Require a loaded TLS context and avoid all-interface cleartext binding."""
        context = Mock()
        app = Mock()
        with patch.dict(
            os.environ,
            {
                "HACKGPT_API_TLS_CERT": "fixture.crt",
                "HACKGPT_API_TLS_KEY": "fixture.key",
                "HACKGPT_API_BIND": "127.0.0.1",
            },
        ), patch("ssl.SSLContext", return_value=context), patch.object(
            self.owner, "create_api_app", return_value=app
        ):
            self.assertIs(self.owner.start_api_server(), True)
        context.load_cert_chain.assert_called_once_with(
            certfile="fixture.crt", keyfile="fixture.key"
        )
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        app.run.assert_called_once_with(
            host="127.0.0.1",
            port=8000,
            ssl_context=context,
            debug=False,
            use_reloader=False,
        )

    def target_info(self):
        """Return only synthetic identifiers for inert phase execution."""
        return {
            "target": "fixture.invalid",
            "scope": "offline fixture",
            "auth_key": "synthetic-reference",
            "assessment_type": "black-box",
            "created_by": "verified-user",
        }

    def test_failed_or_missing_phase_success_never_completes(self):
        """A negative, missing, or malformed result must be durably failed."""
        for result in ({"success": False}, {}, None):
            with self.subTest(result=result):
                self.owner.db.update_session_status.reset_mock()
                self.phases.phase2_scanning_enumeration.return_value = result
                self.assertIs(
                    self.owner.run_full_enterprise_pentest(self.target_info()), False
                )
                self.owner.db.update_session_status.assert_called_once_with(
                    "synthetic-session", "failed", "verified-user"
                )
        self.phases.phase3_vulnerability_assessment.assert_not_called()

    def test_phase_constructor_failure_is_persisted(self):
        """Initialization errors after DB creation cannot strand a running record."""
        self.namespace["EnterprisePentestingPhases"].side_effect = RuntimeError(
            "synthetic failure"
        )
        self.assertIs(self.owner.run_full_enterprise_pentest(self.target_info()), False)
        self.owner.db.update_session_status.assert_called_once_with(
            "synthetic-session", "failed", "verified-user"
        )

    def test_all_successful_phases_persist_completion(self):
        """Only successful completion of every inert phase produces completed."""
        self.assertIs(self.owner.run_full_enterprise_pentest(self.target_info()), True)
        self.owner.db.update_session_status.assert_called_once_with(
            "synthetic-session", "completed", "verified-user"
        )

    def test_keyboard_interrupt_persists_cancelled(self):
        """Cancellation remains distinguishable from failed and completed states."""
        self.phases.phase1_reconnaissance.side_effect = KeyboardInterrupt()
        self.assertIs(self.owner.run_full_enterprise_pentest(self.target_info()), False)
        self.owner.db.update_session_status.assert_called_once_with(
            "synthetic-session", "cancelled", "verified-user"
        )


if __name__ == "__main__":
    unittest.main()
