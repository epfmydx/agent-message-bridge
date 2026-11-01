"""Optional participant notifications, separate from client authentication."""
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

from .errors import Conflict, Invalid
from .network import _InvalidDestination, _parse_destination


def legacy_recipient(settings, participant):
    return participant.id == settings.get("WEBHOOK_PARTICIPANT_ID")


def generation(participant):
    return participant.webhook_generation or 1


def should_notify(settings, participant):
    if participant.webhook_enabled is None:
        # Preserve retained retries even when the legacy callback is not set.
        return legacy_recipient(settings, participant)
    return participant.webhook_enabled


def _stored(settings, participant):
    if participant.webhook_url and participant.webhook_token:
        return participant.webhook_url, participant.webhook_token, None
    if legacy_recipient(settings, participant):
        return settings.get("WEBHOOK_URL", ""), None, settings.get("WEBHOOK_TOKEN", "")
    return "", None, ""


def view_webhook(settings, participant):
    url, encrypted, raw = _stored(settings, participant)
    state = ("inherited" if legacy_recipient(settings, participant) else "unconfigured") if participant.webhook_enabled is None else (
        "enabled" if participant.webhook_enabled else "disabled")
    try:
        hostname = urlsplit(url).hostname if url else None
    except ValueError:
        hostname = None
    return dict(state=state, hostname=hostname, generation=generation(participant), configured=bool(url and (encrypted or raw)))


def update_webhook(db, settings, participant, *, enabled, url="", token="", expected_generation):
    """Caller locks the participant and owns commit; never contact the receiver.

    NULL retains the legacy deployment callback. An explicit off marker always
    overrides it. Generation changes fence queued work, without backfilling old
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
        current_url, encrypted, legacy_token = _stored(settings, participant)
        if participant.webhook_enabled is None and legacy_recipient(settings, participant) and not url.strip() and not token:
            # The legacy queue also exists while deployment credentials are
            # missing; an unchanged form must not cancel its retained retries.
            return False
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
        if not token and not (encrypted or legacy_token):
            raise Invalid("A webhook token is required")
        if not token and target == current_url and should_notify(settings, participant):
            return False
        cipher = Fernet(settings["ENCRYPTION_KEY"].encode())
        if token:
            encrypted = cipher.encrypt(token.encode()).decode()
        elif not encrypted:
            encrypted = cipher.encrypt(legacy_token.encode()).decode()
        participant.webhook_url, participant.webhook_token = target, encrypted
        participant.webhook_enabled = True
    participant.webhook_generation = generation(participant) + 1
    db.flush()
    return True


def callback(settings, participant):
    if not should_notify(settings, participant):
        return None, None
    if participant.webhook_enabled is None:
        return settings.get("WEBHOOK_URL"), settings.get("WEBHOOK_TOKEN")
    return participant.webhook_url, Fernet(settings["ENCRYPTION_KEY"].encode()).decrypt(participant.webhook_token.encode()).decode()


def current_delivery(settings, participant, delivery):
    expected = delivery.webhook_generation
    if expected is None:
        # Old rows and old API writers have no snapshot. They only belong to
        # the original legacy generation, never a later UI configuration.
        if delivery.kind != "webhook" or not legacy_recipient(settings, participant):
            return False
        expected = 1
    return expected == generation(participant) and should_notify(settings, participant)
