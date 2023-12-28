"""
Valorant API Wrapper Library
"""

__version__ = '1.0.0'
__author__ = 'Oliwier Sporny'
__license__ = 'MIT'

from valowrapper.api import API
from valowrapper.errors import (
    BadRequest, Forbidden, HTTPException, NotFound, TooManyRequests,
    ValowrapperException, OriginServerError, Unauthorized
)

api = API()