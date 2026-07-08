class ConfigError(Exception):
    """A configuration file could not be understood.

    Raised for real syntax errors and for constructs this compiler does
    not support yet. Unsupported constructs must fail loudly, never be
    skipped silently.
    """

    def __init__(self, message, path=None, lineno=None):
        self.path = path
        self.lineno = lineno
        where = f"{path}:{lineno}: " if path else ""
        super().__init__(where + message)
