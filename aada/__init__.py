__version__ = "0.1.3"

LOGIN_URL = 'https://login.microsoftonline.com'
MFA_WAIT_METHODS = ('PhoneAppNotification', 'TwoWayVoiceMobile')
MFA_ALLOWED_METHODS = ('PhoneAppOTP', 'OneWaySMS') + MFA_WAIT_METHODS
