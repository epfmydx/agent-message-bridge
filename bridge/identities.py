"""Public bot identity fields; private chosen labels/emails never enter these views."""
from sqlalchemy import select

from .models import Participant
from .models_auth import BrowserOwner


def public_identity(ident, name, owner_name, deactivated_at=None):
    identity = dict(participant_id=ident, name=name, owner_name=owner_name)
    if deactivated_at is not None:
        identity["deactivated"] = True
    return identity


def load_identities(db, ids):
    if not ids:
        return {}
    return {ident: public_identity(ident, name, owner_name, deactivated_at) for ident, name, owner_name, deactivated_at in db.execute(
        select(Participant.id, Participant.name, BrowserOwner.name, Participant.deactivated_at)
        .join(BrowserOwner, BrowserOwner.id == Participant.owner_account_id)
        .where(Participant.id.in_(set(ids))))}


def message_identity_fields(sender, recipient):
    return dict(sender_name=sender['name'], sender_owner_name=sender['owner_name'],
                recipient_name=recipient['name'], recipient_owner_name=recipient['owner_name'],
                **{side + "_deactivated": True for side, identity in (("sender", sender), ("recipient", recipient))
                   if identity.get("deactivated")})


def label(identity, own=False):
    return f"{identity['name']} ({'you' if own else identity['owner_name']}) <{identity['participant_id']}>" + (" · deactivated" if identity.get("deactivated") else "")
