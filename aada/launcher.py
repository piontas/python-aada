import os
import shutil
from typing import Any
from pyppeteer.launcher import Launcher
from pyppeteer.browser import Browser


class HeadLessLauncher(Launcher):
    """Chromium parocess launcher class."""

    def connect(self, browserWSEndpoint: str,
                ignoreHTTPSErrors: bool = False) -> Browser:
        pass

    def _cleanup_tmp_user_data_dir(self) -> None:
        if self._tmp_user_data_dir and os.path.exists(self._tmp_user_data_dir):
            shutil.rmtree(self._tmp_user_data_dir, True)


def launch(options: dict = None, **kwargs: Any) -> Browser:
    """Start chromium process and return `Browser` object."""
    return HeadLessLauncher(options, **kwargs).launch()
