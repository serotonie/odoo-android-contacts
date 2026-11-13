import re
import secrets
import time
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlencode, urlsplit

from odoo import Command
from odoo.tests import HttpCase, tagged

from ..controllers.contacts import challenge_for, digest


@tagged("post_install", "-at_install")
class TestAndroidContacts(HttpCase):
    def test_authorize_exchange_and_scope(self):
        self.authenticate("admin", "admin", session_extra={"identity-check-last": time.time()})
        verifier = secrets.token_urlsafe(32)
        state = secrets.token_urlsafe(32)
        challenge = challenge_for(verifier)
        params = {"challenge": challenge, "state": state}
        page = self.url_open("/android-contacts/authorize?" + urlencode(params))
        self.assertEqual(page.status_code, 200)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = self.url_open(
            "/android-contacts/authorize",
            data={**params, "csrf_token": csrf, "decision": "allow"},
            allow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        callback = parse_qs(urlsplit(response.headers["Location"]).query)
        self.assertEqual(callback["state"], [state])
        code = callback["code"][0]

        invalid = self.url_open("/android-contacts/exchange", json={
            "code": code, "verifier": secrets.token_urlsafe(32),
        })
        self.assertEqual(invalid.status_code, 401)
        response = self.url_open("/android-contacts/exchange", json={
            "code": code, "verifier": verifier,
        })
        self.assertEqual(response.status_code, 200, response.text)
        key = response.json()["key"]
        keys = self.env["res.users.apikeys"].sudo().search([
            ("scope", "=", "ch.laudhair.odoo.android.contacts"),
            ("user_id", "=", self.env.ref("base.user_admin").id),
        ])
        self.assertEqual(len(keys), 1)
        remaining = keys.expiration_date - datetime.utcnow()
        self.assertGreater(remaining, timedelta(days=89))
        self.assertLessEqual(remaining, timedelta(days=90))
        replay = self.url_open("/android-contacts/exchange", json={
            "code": code, "verifier": verifier,
        })
        self.assertEqual(replay.status_code, 401)

        headers = {"Authorization": "bearer " + key}
        identity = self.url_open("/android-contacts/identity", json={}, headers=headers, method="POST")
        self.assertEqual(identity.status_code, 200)
        self.assertEqual(identity.json()["uid"], self.env.ref("base.user_admin").id)
        contacts = self.url_open("/android-contacts/contacts", json={"after": 0}, headers=headers)
        self.assertEqual(contacts.status_code, 200, contacts.text)
        self.assertIsInstance(contacts.json(), list)
        generic = self.url_open("/json/2/res.users/context_get", json={}, headers=headers, method="POST")
        self.assertEqual(generic.status_code, 401)
        keys._remove()
        revoked = self.url_open("/android-contacts/identity", json={}, headers=headers, method="POST")
        self.assertEqual(revoked.status_code, 401)

    def test_consent_requires_csrf(self):
        self.authenticate("admin", "admin")
        response = self.url_open("/android-contacts/authorize", data={
            "challenge": secrets.token_urlsafe(32),
            "state": secrets.token_urlsafe(32),
            "decision": "allow",
        })
        self.assertEqual(response.status_code, 400)

    def test_consent_requires_recent_identity(self):
        self.authenticate("admin", "admin")
        params = {
            "challenge": secrets.token_urlsafe(32),
            "state": secrets.token_urlsafe(32),
        }
        page = self.url_open("/android-contacts/authorize?" + urlencode(params))
        self.assertIn('name="password"', page.text)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        form = {**params, "csrf_token": csrf, "decision": "allow"}
        missing = self.url_open("/android-contacts/authorize", data=form)
        self.assertEqual(missing.status_code, 403)
        invalid = self.url_open("/android-contacts/authorize", data={**form, "password": "incorrect"})
        self.assertEqual(invalid.status_code, 403)
        valid = self.url_open(
            "/android-contacts/authorize",
            data={**form, "password": "admin"},
            allow_redirects=False,
        )
        self.assertEqual(valid.status_code, 303, valid.text)

    def test_expired_code_is_rejected(self):
        verifier = secrets.token_urlsafe(32)
        code = secrets.token_urlsafe(32)
        self.env["odoo.android.authorization"].sudo().create({
            "code_hash": digest(code),
            "challenge": challenge_for(verifier),
            "user_id": self.env.ref("base.user_admin").id,
            "expires_at": datetime.utcnow() - timedelta(hours=1),
        })
        response = self.url_open("/android-contacts/exchange", json={
            "code": code, "verifier": verifier,
        })
        self.assertEqual(response.status_code, 401)

    def test_user_without_key_permission_cannot_authorize(self):
        user = self.env["res.users"].sudo().create({
            "name": "Portal test",
            "login": "portal-test",
            "group_ids": [Command.set([self.env.ref("base.group_portal").id])],
        })
        self.authenticate(user.login, "unused", session_extra={"identity-check-last": time.time()})
        params = {
            "challenge": secrets.token_urlsafe(32),
            "state": secrets.token_urlsafe(32),
        }
        page = self.url_open("/android-contacts/authorize?" + urlencode(params))
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = self.url_open("/android-contacts/authorize", data={
            **params, "csrf_token": csrf, "decision": "allow",
        })
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.env["odoo.android.authorization"].sudo().search_count([]), 0)
