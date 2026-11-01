class Invalid(ValueError):
    pass


class Conflict(ValueError):
    pass


class Unavailable(ValueError):
    pass


class StorageUnavailable(Unavailable):
    """Retryable file storage/transfer failure, distinct from a missing resource."""
    pass
