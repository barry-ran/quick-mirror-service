#!/usr/bin/env python3
"""Create one QM application, or validate an existing one; never update policies."""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


class SetupError(Exception):
    pass


def identifier(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise SetupError("INVALID_UUID") from None
    return value


def application_payload(role, name):
    if role not in ("pc", "mobile") or not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise SetupError("INVALID_APPLICATION")
    return {"name": name, "registration_mode": "grant", "require_target_approval": role == "mobile"}


def validate_application(app, role, tenant):
    if not isinstance(app, dict):
        raise SetupError("INVALID_APPLICATION_RESPONSE")
    identifier(app.get("id"))
    if (app.get("tenant_id") != tenant or app.get("enabled") is not True
            or app.get("registration_mode") != "grant"
            or app.get("require_target_approval") is not (role == "mobile")):
        raise SetupError("APPLICATION_POLICY_MISMATCH")
    return app


def initialize(call, role, tenant, name=None, operation=None, existing=None):
    identifier(tenant)
    if role not in ("pc", "mobile"):
        raise SetupError("INVALID_ROLE")
    if existing:
        if operation:
            raise SetupError("EXISTING_IS_READ_ONLY")
        result = call("GET", "/v1/applications/" + identifier(existing), None, None, 200)
    else:
        identifier(operation)
        result = call("POST", "/v1/applications", application_payload(role, name), operation, 201)
    result = validate_application(result, role, tenant)
    if existing and result["id"] != existing:
        raise SetupError("APPLICATION_ID_MISMATCH")
    if name is not None and result.get("name") != name:
        raise SetupError("APPLICATION_NAME_MISMATCH")
    if not existing:
        # Creation receipts can be replayed after an operator changed policy.
        current = call("GET", "/v1/applications/" + result["id"], None, None, 200)
        validate_application(current, role, tenant)
        if current.get("id") != result["id"] or current.get("name") != name:
            raise SetupError("APPLICATION_IDENTITY_MISMATCH")
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SetupError("REDIRECT_REFUSED")


class Client:
    def __init__(self, origin, credential_file, ca_file=None):
        parsed = urllib.parse.urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path or parsed.query or parsed.fragment):
            raise SetupError("INVALID_HTTPS_ORIGIN")
        try:
            with Path(credential_file).open("rb") as source:
                raw = source.read(16385)
            if len(raw) > 16384:
                raise ValueError()
            token = json.loads(raw)["service_credential"]
            if not isinstance(token, str) or not 1 <= len(token) <= 512 or any(not 33 <= ord(c) <= 126 for c in token):
                raise ValueError()
        except (OSError, ValueError, KeyError, TypeError):
            raise SetupError("INVALID_CREDENTIAL_FILE") from None
        self.origin, self.token = origin, token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def call(self, method, path, body, key, expected):
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        if key:
            headers["Idempotency-Key"] = key
        request = urllib.request.Request(self.origin + path, method=method, headers=headers,
            data=None if body is None else json.dumps(body).encode())
        try:
            with self.opener.open(request, timeout=15) as response:
                if response.status != expected:
                    raise SetupError("UNEXPECTED_HTTP_STATUS")
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise SetupError("RESPONSE_TOO_LARGE")
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            raise SetupError("HTTP_" + str(error.code)) from None
        except (urllib.error.URLError, OSError, ValueError):
            raise SetupError("REQUEST_FAILED") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--credential-file", required=True)
    parser.add_argument("--ca-file")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--role", choices=("pc", "mobile"), required=True)
    parser.add_argument("--name")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--operation-id", help="Keep this UUID and all inputs unchanged when retrying")
    choice.add_argument("--existing-id", help="Read-only policy check; never PATCH existing applications")
    args = parser.parse_args()
    try:
        identifier(args.tenant)
        client = Client(args.origin, args.credential_file, args.ca_file)
        own = client.call("GET", "/v1/service-credentials/self", None, None, 200)
        if not isinstance(own, dict) or own.get("tenant_id") != args.tenant or own.get("scope") != "admin":
            raise SetupError("SERVICE_PRINCIPAL_MISMATCH")
        result = initialize(client.call, args.role, args.tenant, args.name, args.operation_id, args.existing_id)
        print(json.dumps({"application_id": result["id"], "tenant_id": args.tenant,
            "role": args.role, "require_target_approval": result["require_target_approval"]}))
        return 0
    except SetupError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
