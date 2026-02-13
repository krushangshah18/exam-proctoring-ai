import logging
import os
from datetime import datetime , UTC
from pathlib import Path
from logging.handlers import RotatingFileHandler

from dotenv import load_dotenv
load_dotenv()

# ENV CONFIG
ENV = os.getenv("ENV", "development").lower()

BASE_LOG_DIR = Path("logs")

def get_today_dir():
    """
    Returns today's log directory path
    """
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    path = BASE_LOG_DIR / today
    path.mkdir(parents=True, exist_ok=True)
    return path

# FORMATTER
LOG_FORMAT = (
    "[%(asctime)s] "
    "[%(levelname)s] "
    "[%(name)s] "
    "[%(filename)s:%(lineno)d] "
    "%(message)s"
)

formatter = logging.Formatter(LOG_FORMAT)

# HANDLER FACTORY
def create_rotating_handler(filename, max_mb=10, backups=5):
    log_dir = get_today_dir()
    log_file = log_dir / filename

    handler = RotatingFileHandler(log_file, maxBytes=max_mb*1024*1024, backupCount=backups, encoding="utf-8")

    handler.setFormatter(formatter)
    return handler

# LOGGER SETUP
def setup_logger(name, file_name):
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger
    
    logger.setLevel(logging.DEBUG if ENV == "development" else logging.INFO)

    #File handler
    file_handler = create_rotating_handler(file_name)
    logger.addHandler(file_handler)

    # Console (dev only)
    if ENV == "development":
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)

    logger.propagate = False

    return logger

# PUBLIC LOGGERS
log = setup_logger(
    name="exam_proctoring.app",
    file_name="app.log"
)

system_logger = setup_logger(
    name="exam_proctoring.system",
    file_name="system.log"
)
