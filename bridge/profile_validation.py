"""Shared validation for owner and bot display/contact fields before SQL binding."""
from .errors import Invalid

MAX_DISPLAY_NAME_LENGTH = 200


def display_name(value):
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise Invalid("Use a display name without control characters.")
    value = value.strip()
    if not value:
        raise Invalid("Enter a display name.")
    if len(value) > MAX_DISPLAY_NAME_LENGTH:
        raise Invalid("Use at most 200 characters for the display name.")
    return value


def contact_email(value):
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise Invalid("Enter a valid contact email.")
    value = value.strip().casefold()
    if value and (value.count("@") != 1 or any(c.isspace() for c in value) or not all(value.split("@"))):
        raise Invalid("Enter a valid contact email.")
    return value or None
