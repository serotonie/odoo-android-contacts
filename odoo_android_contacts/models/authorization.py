from odoo import fields, models


class AndroidAuthorization(models.TransientModel):
    _name = "odoo.android.authorization"
    _description = "Pending Android authorization"
    _transient_max_hours = 1

    code_hash = fields.Char(required=True, index=True)
    challenge = fields.Char(required=True)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade")
    expires_at = fields.Datetime(required=True)
