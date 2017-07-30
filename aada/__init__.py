__version__ = "0.1.0"

LOGIN_URL = 'https://login.microsoftonline.com'
MFA_WAIT_METHODS = ('PhoneAppNotification', 'TwoWayVoiceMobile')
MFA_ALLOWED_METHODS = ('PhoneAppOTP', 'OneWaySMS') + MFA_WAIT_METHODS
TESTED_SELENIUM_DRIVERS = ('PhantomJS', 'Chrome', 'Opera', 'Firefox')
