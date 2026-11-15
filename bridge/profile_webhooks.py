"""Optional participant notifications, separate from client authentication."""
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

from .errors import Conflict, Invalid
from .network import _InvalidDestination, _parse_destination


def generation(participant):
    return participant.webhook_generation or 1


def should_notify(settings, participant):
    return bool(participant.webhook_enabled)


def view_webhook(settings, participant):
    url, encrypted = participant.webhook_url, participant.webhook_token
    state = "enabled" if participant.webhook_enabled else "disabled"
    try:
        hostname = urlsplit(url).hostname if url else None
    except ValueError:
        hostname = None
    configured = bool(url and encrypted)
    label = "Disabled" if state == "disabled" else "Configured" if configured else "Enabled — not configured"
    return dict(state=state, hostname=hostname, generation=generation(participant), configured=configured, label=label)


def update_webhook(db, settings, participant, *, enabled, url="", token="", expected_generation):
    """Caller locks the participant and owns commit; never contact the receiver.

    Generation changes fence queued work, without backfilling old
    messages or redirecting old notification attempts to a new destination.
    """
    if type(expected_generation) is not int or expected_generation < 1:
        raise Invalid("Invalid notification settings version")
    if generation(participant) != expected_generation:
        raise Conflict("Notification settings changed; reload the form")
    if type(enabled) is not bool or not isinstance(url, str) or not isinstance(token, str):
        raise Invalid("Invalid notification settings")
    if not enabled:
        if participant.webhook_enabled is False:
            return False
        participant.webhook_enabled = False
    else:
        current_url, encrypted = participant.webhook_url, participant.webhook_token
        target = url.strip() or current_url
        try:
            _parse_destination(target)
        except _InvalidDestination:
            raise Invalid("Enter a public HTTPS webhook destination") from None
        if token and any(c in token for c in "\r\n"):
            raise Invalid("Enter a single-line webhook token")
        try:
            token.encode("latin-1")
        except UnicodeEncodeError:
            raise Invalid("Enter an HTTP-compatible webhook token") from None
        if token and token == settings.get("CLOUDFLARE_ORIGIN_SECRET"):
            raise Invalid("Use a dedicated webhook token")
        if target != current_url and not token:
            raise Invalid("Supply the token for the replacement destination")
        if not token and not encrypted:
            raise Invalid("A webhook token is required")
        if not token and target == current_url and should_notify(settings, participant):
            return False
        cipher = Fernet(settings["ENCRYPTION_KEY"].encode())
        if token:
            encrypted = cipher.encrypt(token.encode()).decode()
        participant.webhook_url, participant.webhook_token = target, encrypted
        participant.webhook_enabled = True
    participant.webhook_generation = generation(participant) + 1
    db.flush()
    return True


def callback(settings, participant):
    if not should_notify(settings, participant):
        return None, None
    if not participant.webhook_url or not participant.webhook_token:
        return None, None  # A migrated unconfigured callback retains retry behavior.
    return participant.webhook_url, Fernet(settings["ENCRYPTION_KEY"].encode()).decrypt(participant.webhook_token.encode()).decode()


def current_delivery(settings, participant, delivery):
    expected = delivery.webhook_generation
    if expected is None and participant.legacy_webhook:
        expected = 1
    return expected == generation(participant) and should_notify(settings, participant)
