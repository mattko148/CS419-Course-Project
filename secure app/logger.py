"""
logger.py — Added in week 3.
Structured JSON logging for all security and access events.
Feeds into the audit trail requirement from the spec.
"""
import logging
import json
import os
from datetime import datetime, timezone
from config import Config


def _setup_logger(name: str, filepath: str) -> logging.Logger:
    os.makedirs(Config.LOGS_DIR, exist_ok=True)
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler(filepath)
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
    return logger


_security_logger = _setup_logger('security', Config.SECURITY_LOG)
_access_logger   = _setup_logger('access',   Config.ACCESS_LOG)


def log_security(event_type: str, user_id=None, details=None,
                 severity: str = 'INFO', ip=None, ua=None) -> None:
    entry = {
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'event_type': event_type,
        'user_id':    user_id,
        'ip_address': ip,
        'user_agent': ua,
        'details':    details or {},
        'severity':   severity,
    }
    line = json.dumps(entry)
    match severity:
        case 'CRITICAL': _security_logger.critical(line)
        case 'ERROR':    _security_logger.error(line)
        case 'WARNING':  _security_logger.warning(line)
        case _:          _security_logger.info(line)


def log_access(method: str, path: str, status: int,
               user_id=None, ip=None) -> None:
    entry = {
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'method':     method,
        'path':       path,
        'status':     status,
        'user_id':    user_id,
        'ip_address': ip,
    }
    _access_logger.info(json.dumps(entry))