import asyncio
import logging
from typing import Any, Dict, List, TYPE_CHECKING

from pyppeteer.launcher import Launcher, DEFAULT_ARGS, AUTOMATION_ARGS
from pyppeteer.browser import Browser
from pyppeteer.util import check_chromium, chromium_executable
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
        self.chrome_args: List[str] = []
        self._loop = self.options.get('loop', asyncio.get_event_loop())

        log_level = self.options.get('logLevel')
        if log_level:
            logging.getLogger('pyppeteer').setLevel(log_level)

        if not self.options.get('ignoreDefaultArgs', False):
            self.chrome_args.extend(DEFAULT_ARGS)
            self.chrome_args.append(
                f'--remote-debugging-port={self.port}',
            )

        self.chromeClosed = True
        if self.options.get('appMode', False):
            self.options['headless'] = False
        elif not self.options.get('ignoreDefaultArgs', False):
            self.chrome_args.extend(AUTOMATION_ARGS)

        self._tmp_user_data_dir: Optional[str] = None
        self._parse_args()

        if self.options.get('devtools'):
            self.chrome_args.append('--auto-open-devtools-for-tabs')
            self.options['headless'] = False

        if 'headless' not in self.options or self.options.get('headless'):
            self.chrome_args.extend([
                '--headless',
                '--disable-gpu',
                '--hide-scrollbars',
                '--mute-audio',
            ])

        def _is_default_url() -> bool:
            for arg in self.options['args']:
                if not arg.startswith('-'):
                    return False
            return True

        if (not self.options.get('ignoreDefaultArgs') and
                isinstance(self.options.get('args'), list) and
                _is_default_url()):
            self.chrome_args.append('about:blank')

        if 'executablePath' in self.options and self.options['executablePath'] is not None:
            self.exec = self.options['executablePath']
        else:
            if not check_chromium():
                download_chromium()
            self.exec = str(chromium_executable())

        self.cmd = [self.exec] + self.chrome_args


async def launch(options: dict = None, **kwargs: Any) -> Browser:
    return await HeadLessLauncher(options, **kwargs).launch()
