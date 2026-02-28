import logging
import threading
import sys
import os
import re
from collections import deque
from datetime import datetime
from src.repo_manager import update_payloads
from src.update_checker import check_for_updates

if sys.platform == 'win32':
    os.system('')

LOG_BUFFER = deque(maxlen=2000)


class ColorFormatter(logging.Formatter):
    
    RESET  = '\033[0m'
    COLORS = {
        logging.DEBUG:    '\033[36m',
        logging.INFO:     '\033[32m',
        logging.WARNING:  '\033[33;1m',
        logging.ERROR:    '\033[31;1m',
        logging.CRITICAL: '\033[41;37;1m', 
    }
    GREY   = '\033[90m'
    NAME_C = '\033[35m'

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        lvl   = f"{color}[{record.levelname}]{self.RESET}"
        ts    = f"{self.GREY}{self.formatTime(record)}{self.RESET}"
        name  = f"{self.NAME_C}{record.name}{self.RESET}"
        msg   = record.getMessage()
        return f"{ts} {lvl} {name}: {msg}"


class ListHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            LOG_BUFFER.append(msg)
        except Exception:
            self.handleError(record)


TAG_COLORS = {
    'STARTUP':  '\033[34;1m',
    'DNS':      '\033[36;1m',
    'AJB':      '\033[33m',
    'SEND':     '\033[32;1m',
    'MANUAL':   '\033[32m',
    'UPLOAD':   '\033[32m',
    'DOWNLOAD': '\033[32m',
    'REPO':     '\033[35m',
    'TOOL':     '\033[35;1m',
    'WAIT':     '\033[90m',
    'SKIP':     '\033[90m',
    'FAIL':     '\033[31;1m',
    'ERROR':    '\033[31;1m',
    'DELETE':   '\033[31m',
    'SORT':     '\033[33m',
}
RESET = '\033[0m'
GREY  = '\033[90m'

_TAG_RE = re.compile(r'^\[([A-Z]+)\]')

def _colorize_print(text):
    m = _TAG_RE.match(text)
    if m:
        tag = m.group(1)
        color = TAG_COLORS.get(tag)
        if color:
            return f"{color}{text}{RESET}"
    if text.startswith('---') and text.endswith('---'):
        return f"\033[34;1m{text}{RESET}"
    return text


class StdoutCapture:
    def __init__(self, stream):
        self.stream = stream
        self.encoding = stream.encoding

    def write(self, data):
        stripped = data.strip()
        if stripped:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
            colored = _colorize_print(stripped)
            self.stream.write(f"{GREY}{ts}{RESET} {colored}\n")
            LOG_BUFFER.append(f"{ts} [STDOUT] {stripped}")
        elif data == '\n':
            pass
        else:
            self.stream.write(data)
        self.stream.flush()

    def flush(self):
        self.stream.flush()

def setup_logging(config):
    level = logging.DEBUG if config.get("debug_mode") == "true" else logging.INFO
    
    list_handler = ListHandler()
    plain_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    list_handler.setFormatter(plain_formatter)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColorFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers = []
    
    logging.basicConfig(
        level=level,
        handlers=[
            console_handler,
            list_handler
        ],
        force=True
    )
    
    if not isinstance(sys.stdout, StdoutCapture):
        sys.stdout = StdoutCapture(sys.stdout)

    logger = logging.getLogger("Y2JB")
    logger.info(f"Logging initialized at {'DEBUG' if level == logging.DEBUG else 'INFO'} level")

def run_startup_tasks(config):
    if config.get("auto_update_repos", "true") == "true":
        print("[STARTUP] Auto-updating repositories...")
        threading.Thread(target=lambda: update_payloads(['all']), daemon=True).start()
    
    print("[STARTUP] Checking for codebase updates...")
    threading.Thread(target=check_for_updates, daemon=True).start()

def get_logs():
    return list(LOG_BUFFER)