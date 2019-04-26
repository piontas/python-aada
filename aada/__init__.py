__version__ = "0.1.7"

try:
    import keyring  # noqa
except ImportError:
    KEYRING = False
else:
    KEYRING = True

LOGIN_URL = 'https://login.microsoftonline.com'
MFA_WAIT_METHODS = ('PhoneAppNotification', 'TwoWayVoiceMobile')
MFA_ALLOWED_METHODS = ('PhoneAppOTP', 'OneWaySMS') + MFA_WAIT_METHODS
