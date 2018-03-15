import os
import shutil
from typing import Any, Dict, TYPE_CHECKING
from pyppeteer.launcher import Launcher, DEFAULT_ARGS, AUTOMATION_ARGS
from pyppeteer.browser import Browser
from pyppeteer.util import check_chromium, chromium_excutable
from pyppeteer.util import download_chromium, merge_dict, get_free_port

if TYPE_CHECKING:
    from typing import Optional


class HeadLessLauncher(Launcher):
    """Chromium parocess launcher class."""

    def __init__(self, options: Dict[str, Any] = None, **kwargs: Any) -> None:
        """Make new launcher."""
        self.options = merge_dict(options, kwargs)
        self.port = get_free_port()
        self.url = f'http://127.0.0.1:{self.port}'

        self.chrome_args = DEFAULT_ARGS
        self.chrome_args.append(
            f'--remote-debugging-port={self.port}',
        )
        self.chromeClosed = True
        if self.options.get('appMode', False):
            self.options['headless'] = False
        else:
            self.chrome_args.extend(AUTOMATION_ARGS)

        self._tmp_user_data_dir: Optional[str] = None
        self._parse_args()

        if self.options.get('devtools'):
            self.chrome_args.append('--auto-open-devtools-for-tabs')
            self.options['headless'] = False

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

    def _cleanup_tmp_user_data_dir(self) -> None:
        if self._tmp_user_data_dir and os.path.exists(self._tmp_user_data_dir):
            shutil.rmtree(self._tmp_user_data_dir, True)


async def launch(options: dict = None, **kwargs: Any) -> Browser:
    return await HeadLessLauncher(options, **kwargs).launch()
