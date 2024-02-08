#!/usr/bin/env python3
'''Module for storing the filtered_logger function.'''
import re
from typing import List
import logging
import os


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    '''Returns the log message obfuscated.'''
    for field in fields:
        message = re.sub(rf'{field}=.*?{separator}',
                         f'{field}={redaction}{separator}', message)
    return message
