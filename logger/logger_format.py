import logging

LOGGER = logging.getLogger()
try:
    HANDLER = LOGGER.handlers[0]
except IndexError:
    # This is required for local testing
    HANDLER = logging.StreamHandler()
    LOGGER.addHandler(HANDLER)
LOGFORMAT = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
HANDLER.setFormatter(logging.Formatter(LOGFORMAT, "%Y-%m-%d %H:%M:%S"))
LOGGER.setLevel(logging.INFO)