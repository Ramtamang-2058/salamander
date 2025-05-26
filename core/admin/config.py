class AdminConfig:
    # Pagination
    USERS_PER_PAGE = 20
    PAYMENTS_PER_PAGE = 20
    LOGS_PER_PAGE = 50

    # Dashboard
    RECENT_USERS_LIMIT = 5
    RECENT_LOGS_LIMIT = 10
    CHART_DAYS = 30

    # Security
    SESSION_TIMEOUT = 3600  # 1 hour in seconds
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes in seconds

    # File upload limits (for future features)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

    # Export formats
    ALLOWED_EXPORT_FORMATS = ['csv', 'xlsx', 'json']