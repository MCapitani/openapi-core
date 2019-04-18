class Security(object):
    """Represents an OpenAPI Security requirement object."""

    def __init__(self, security_names):
        self.security_names = security_names and dict(security_names) or {}
