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

#a private function only used in logger.py to set up a logging object to write to a specific file 
def _setup_logger(name: str, filepath: str) -> logging.Logger:
    #create the directory for logs if it doesnt already exist
    os.makedirs(Config.LOGS_DIR, exist_ok=True)
    #make the logger variable point to a logging object with name if it exists, and if not then create one with the name
    logger = logging.getLogger(name)
    #this check "did this logging object exist already or is it new?"
    #to do this it checks the handlers and if they are set then it already existed, so no need to change anything
    #if it did not exist, aka "if not logger.handlers", then set these settings
    if not logger.handlers:
        #setting the minimum level to actually log. DEBUG is the lowest so LOG EVERYTHING!
        logger.setLevel(logging.DEBUG)
        #tell it where to write the logs (which file)
        handler = logging.FileHandler(filepath)
        #formats the message for each line, this just gives the message with no formatting
        handler.setFormatter(logging.Formatter('%(message)s'))
        #add the handler to the logger
        logger.addHandler(handler)
    return logger

#logger to record each security event to security.log
_security_logger = _setup_logger('security', Config.SECURITY_LOG)
#logger to record each access to access.log
_access_logger   = _setup_logger('access',   Config.ACCESS_LOG)


def log_security(event_type: str, user_id=None, details=None,
                 severity: str = 'INFO', ip=None, ua=None) -> None:
    #create a dictionary with all of the info about this event
    entry = {
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'event_type': event_type,
        'user_id':    user_id,
        'ip_address': ip,
        'user_agent': ua,
        'details':    details or {},
        'severity':   severity,
    }
    #converts all this stuff into a json string
    line = json.dumps(entry)
    #log the severity of each event
    #this writes ALL events, since we set the minimum level to record as DEBUG.
    #ranks from lowest level to highest is: DEBUG, INFO, WARNING, ERROR, CRITICAL
    match severity:
        case 'CRITICAL': _security_logger.critical(line)
        case 'ERROR':    _security_logger.error(line)
        case 'WARNING':  _security_logger.warning(line)
        case _:          _security_logger.info(line)


def log_access(method: str, path: str, status: int,
               user_id=None, ip=None) -> None:
    #creating a dictionary again of the access event
    #records what happened, like the http method, url path, response status code, who made the request (what OS and browser), and lastly their IP address
    entry = {
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'method':     method,
        'path':       path,
        'status':     status,
        'user_id':    user_id,
        'ip_address': ip,
    }
    #writes the event to access.log
    _access_logger.info(json.dumps(entry))