import os
import shutil
from typing import Any, Dict
from pyppeteer.launcher import Launcher, DEFAULT_ARGS
from pyppeteer.browser import Browser
from pyppeteer.util import check_chromium, chromium_excutable
from pyppeteer.util import download_chromium


class HeadLessLauncher(Launcher):
    """Chromium parocess launcher class."""

    def __init__(self, options: Dict[str, Any] = None, **kwargs: Any) -> None:
        """Make new launcher."""
        self.options = options or dict()
        self.options.update(kwargs)
        self.chrome_args = DEFAULT_ARGS
        self._tmp_user_data_dir = None
        self._parse_args()
        if 'headless' not in self.options or self.options.get('headless'):
            self.chrome_args = self.chrome_args + [
                '--headless',
                '--disable-gpu',
                '--hide-scrollbars',
                '--mute-audio',
            ]
        if self.options.get('executablePath'):
            self.exec = self.options['executablePath']
        else:
            if not check_chromium():
                download_chromium()
            self.exec = str(chromium_excutable())
        self.cmd = [self.exec] + self.chrome_args

    def connect(self, browserWSEndpoint: str,
                ignoreHTTPSErrors: bool = False) -> Browser:
        pass

    def _cleanup_tmp_user_data_dir(self) -> None:
        if self._tmp_user_data_dir and os.path.exists(self._tmp_user_data_dir):
            shutil.rmtree(self._tmp_user_data_dir, True)


def launch(options: dict = None, **kwargs: Any) -> Browser:
    """Start chromium process and return `Browser` object."""
    return HeadLessLauncher(options, **kwargs).launch()
