import base64
import hashlib
import re
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode

from markupsafe import escape
from werkzeug.exceptions import BadRequest, Unauthorized

from odoo import fields, http
from odoo.exceptions import ValidationError
from odoo.http import request


SCOPE = "ch.laudhair.odoo.android.contacts"
CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
NO_STORE = [("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer")]


def digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def challenge_for(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


class AndroidContacts(http.Controller):
    @http.route("/android-contacts/authorize", type="http", auth="user", methods=["GET", "POST"])
    def authorize(self, challenge=None, state=None, decision=None, **kwargs):
        if not isinstance(challenge, str) or not CHALLENGE.fullmatch(challenge):
            raise BadRequest()
        if not isinstance(state, str) or not CHALLENGE.fullmatch(state):
            raise BadRequest()
        if request.httprequest.method == "POST":
            params = {"state": state}
            if decision == "allow":
                code = secrets.token_urlsafe(32)
                request.env["odoo.android.authorization"].sudo().create({
                    "code_hash": digest(code),
                    "challenge": challenge,
                    "user_id": request.env.uid,
                    "expires_at": fields.Datetime.now() + timedelta(minutes=5),
                })
                params.update(code=code, database=request.db)
            elif decision == "deny":
                params["error"] = "denied"
            else:
                raise BadRequest()
            response = request.redirect("/android-contacts/callback?" + urlencode(params))
            response.headers.extend(NO_STORE)
            return response

        html = f"""<!doctype html><html lang="fr"><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Autoriser les contacts Android</title></head><body>
<h1>Autoriser les contacts Android</h1>
<p>Connecté en tant que {escape(request.env.user.display_name)}.</p>
<p>Autoriser l'application à lire vos contacts Odoo pendant 90 jours, même lorsque
vous n'utilisez pas l'application ? Les contacts seront copiés sur votre téléphone.</p>
<form method="post">
<input type="hidden" name="csrf_token" value="{escape(request.csrf_token())}">
<input type="hidden" name="challenge" value="{escape(challenge)}">
<input type="hidden" name="state" value="{escape(state)}">
<button type="submit" name="decision" value="allow">Autoriser</button>
<button type="submit" name="decision" value="deny">Annuler</button>
</form></body></html>"""
        return request.make_response(html, headers=NO_STORE)

    @http.route("/android-contacts/exchange", type="http", auth="public", methods=["POST"], csrf=False, save_session=False)
    def exchange(self, **kwargs):
        data = request.httprequest.get_json(silent=True)
        if not isinstance(data, dict):
            raise BadRequest()
        code = data.get("code")
        verifier = data.get("verifier")
        if not isinstance(code, str) or not CHALLENGE.fullmatch(code):
            raise BadRequest()
        if not isinstance(verifier, str) or not CHALLENGE.fullmatch(verifier):
            raise BadRequest()
        request.env.cr.execute(
            """DELETE FROM odoo_android_authorization
               WHERE code_hash = %s AND challenge = %s AND expires_at > NOW() AT TIME ZONE 'UTC'
               RETURNING user_id""",
            (digest(code), challenge_for(verifier)),
        )
        row = request.env.cr.fetchone()
        if not row:
            raise Unauthorized()
        user = request.env["res.users"].sudo().browse(row[0]).exists()
        if not user or not user.active:
            raise Unauthorized()
        expiry = datetime.utcnow() + timedelta(days=90)
        try:
            key = request.env["res.users.apikeys"].with_user(user)._generate(
                SCOPE, "Android Contacts", expiry,
            )
        except ValidationError:
            return request.make_json_response(
                {"error": "duration_not_allowed"}, headers=NO_STORE, status=422,
            )
        return request.make_json_response({"key": key, "uid": user.id}, headers=NO_STORE)

    def _authenticate(self):
        header = request.httprequest.headers.get("Authorization", "")
        match = re.fullmatch(r"(?i:bearer) ([0-9a-f]{40})", header)
        if not match:
            raise Unauthorized()
        uid = request.env["res.users.apikeys"]._check_credentials(scope=SCOPE, key=match.group(1))
        if not uid:
            raise Unauthorized()
        request.update_env(user=uid, su=False)

    @http.route("/android-contacts/identity", type="http", auth="public", methods=["POST"], csrf=False, save_session=False)
    def identity(self, **kwargs):
        self._authenticate()
        return request.make_json_response({"uid": request.env.uid}, headers=NO_STORE)

    @http.route("/android-contacts/contacts", type="http", auth="public", methods=["POST"], csrf=False, save_session=False)
    def contacts(self, **kwargs):
        self._authenticate()
        data = request.httprequest.get_json(silent=True)
        if not isinstance(data, dict) or type(data.get("after")) is not int or data["after"] < 0:
            raise BadRequest()
        records = request.env["res.partner"].search_read(
            [("id", ">", data["after"])],
            ["id", "name", "display_name", "phone"],
            order="id asc",
            limit=200,
        )
        return request.make_json_response(records, headers=NO_STORE)
