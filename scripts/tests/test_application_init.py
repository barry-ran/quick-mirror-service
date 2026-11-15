import importlib.util
import json
import io
import urllib.error
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("application_init", Path(__file__).parents[1] / "init-peerloom-application.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
TENANT = "11111111-1111-4111-8111-111111111111"
APP = "22222222-2222-4222-8222-222222222222"
OP = "33333333-3333-4333-8333-333333333333"


class Fake:
    def __init__(self, role="mobile"):
        self.calls = []
        self.app = dict(id=APP, tenant_id=TENANT, name="QM", enabled=True,
                        registration_mode="grant", require_target_approval=role == "mobile")
        self.receipts = {}
        self.creates = 0

    def __call__(self, method, path, body, key, status):
        self.calls.append((method, path, body, key, status))
        if method == "POST":
            encoded = json.dumps(body, sort_keys=True)
            if key in self.receipts:
                if self.receipts[key] != encoded:
                    raise module.SetupError("HTTP_409")
            else:
                self.receipts[key] = encoded
                self.creates += 1
            return dict(self.app)
        assert method == "GET"
        return dict(self.app)


class InitializationTest(unittest.TestCase):
    def test_mobile_true_pc_false_exact_payload_and_repeat(self):
        for role in ("mobile", "pc"):
            fake = Fake(role)
            for _ in range(2):
                module.initialize(fake, role, TENANT, "QM", OP)
            self.assertEqual(1, fake.creates)
            self.assertEqual(fake.calls[0], fake.calls[2])
            self.assertEqual({"name": "QM", "registration_mode": "grant",
                              "require_target_approval": role == "mobile"}, fake.calls[0][2])

    def test_existing_only_reads(self):
        fake = Fake()
        module.initialize(fake, "mobile", TENANT, "QM", existing=APP)
        self.assertEqual(["GET"], [call[0] for call in fake.calls])

    def test_existing_wrong_policy_identity_disabled_never_updates(self):
        for field, value in (("require_target_approval", False), ("require_target_approval", 1),
                             ("tenant_id", APP), ("id", TENANT), ("name", "PC"),
                             ("enabled", False), ("registration_mode", "direct")):
            fake = Fake()
            fake.app[field] = value
            with self.assertRaises(module.SetupError):
                module.initialize(fake, "mobile", TENANT, "QM", existing=APP)
            self.assertEqual(["GET"], [call[0] for call in fake.calls])

    def test_creation_failure_has_no_compensating_update_or_pc_call(self):
        calls = []
        def fail(*args):
            calls.append(args)
            raise module.SetupError("HTTP_503")
        with self.assertRaises(module.SetupError):
            module.initialize(fail, "mobile", TENANT, "QM", OP)
        self.assertEqual(1, len(calls))
        self.assertEqual("POST", calls[0][0])
        self.assertTrue(calls[0][2]["require_target_approval"])

    def test_reused_operation_with_different_payload_is_not_retried(self):
        fake = Fake()
        module.initialize(fake, "mobile", TENANT, "QM", OP)
        with self.assertRaisesRegex(module.SetupError, "HTTP_409"):
            module.initialize(fake, "mobile", TENANT, "Changed", OP)
        self.assertEqual(1, fake.creates)
        self.assertEqual(3, len(fake.calls))

    def test_replayed_receipt_checks_current_policy(self):
        fake = Fake()
        def changed(method, *args):
            result = fake(method, *args)
            if method == "GET":
                result["require_target_approval"] = False
            return result
        with self.assertRaisesRegex(module.SetupError, "POLICY_MISMATCH"):
            module.initialize(changed, "mobile", TENANT, "QM", OP)
        self.assertEqual(["POST", "GET"], [call[0] for call in fake.calls])

    def test_invalid_inputs_fail_before_request(self):
        fake = Fake()
        for key in (None, "bad"):
            with self.assertRaises(module.SetupError):
                module.initialize(fake, "mobile", TENANT, "QM", key)
        self.assertEqual([], fake.calls)

    def test_http_contract_uses_direct_json_and_explicit_key(self):
        class Response(io.BytesIO):
            status = 201
        class Opener:
            def open(inner, request, timeout):
                self.assertEqual("POST", request.method)
                self.assertEqual("https://peer.example/v1/applications", request.full_url)
                self.assertEqual(OP, request.get_header("Idempotency-key"))
                self.assertTrue(json.loads(request.data)["require_target_approval"])
                self.assertEqual(15, timeout)
                return Response(json.dumps(Fake().app).encode())
        client = object.__new__(module.Client)
        client.origin, client.token, client.opener = "https://peer.example", "test-only", Opener()
        self.assertEqual(APP, client.call("POST", "/v1/applications",
            module.application_payload("mobile", "QM"), OP, 201)["id"])

    def test_http_failure_never_echoes_response_or_credentials(self):
        class Opener:
            def open(inner, *args, **kwargs):
                raise urllib.error.HTTPError("https://peer.example", 409,
                    "secret-in-reason", {}, io.BytesIO(b"secret-in-body"))
        client = object.__new__(module.Client)
        client.origin, client.token, client.opener = "https://peer.example", "test-secret", Opener()
        with self.assertRaises(module.SetupError) as error:
            client.call("POST", "/v1/applications", {}, OP, 201)
        self.assertEqual("HTTP_409", str(error.exception))

    def test_redirect_cannot_forward_service_credential(self):
        with self.assertRaisesRegex(module.SetupError, "REDIRECT_REFUSED"):
            module.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example")


if __name__ == "__main__":
    unittest.main()
