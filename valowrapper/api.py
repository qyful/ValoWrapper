from valowrapper.errors import (
    BadRequest, Forbidden, HTTPException, NotFound, TooManyRequests,
    ValowrapperException, OriginServerError, Unauthorized
)

import valowrapper

from platform import python_version

import logging
import requests
import sys
import time

log = logging.getLogger(__name__)

class API:
    def __init__(
            self, bearer_token=None, *, host='api.henrikdev.xyz/valorant/v1/', retry_count=0,
            retry_delay=0,retry_errors=None, timeout=60, user_agent=None,
            wait_on_rate_limit=False
    ):
        self.bearer_token = bearer_token
        self.host = host
        self.wait_on_rate_limit = wait_on_rate_limit
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.retry_errors = retry_errors
        self.timeout = timeout

        if user_agent is None:
            user_agent = (
                f"Python/{python_version()} "
                f"Requests/{requests.__version__} "
                f"ValoWrapper/{valowrapper.__version__}"
            )

        self.user_agent = user_agent

        self.session = requests.Session()

    def request(
            self, method, endpoint, *, endpoint_parameters=(), params=None,
            headers=None, json_payload=None, payload_list=False,
            payload_type=None, post_data=None, require_auth=True, **kwargs
    ) -> dict:
        if require_auth and not self.bearer_token:
            raise ValowrapperException('Authentication is required for this endpoint.')
        
        if headers is None:
            headers = {}
        
        headers["User-Agent"] = self.user_agent

        if self.bearer_token: headers["Authorization"] = f"Bearer {self.bearer_token}"

        req_url = "https://" + self.host + endpoint

        if params is None:
            params = {}
        
        for k, arg in kwargs.items():
            if arg is None:
                continue

            if k not in endpoint_parameters:
                log.warning(f"Unexpected parameter: {k}")
            
            params[k] = str(arg)

            log.debug("PARAMS: %r", params)

        remaining_calls = None
        reset_time = None

        try:
            retries_performed = 0

            while retries_performed <= self.retry_count:
                if (self.wait_on_rate_limit and reset_time is not None
                    and remaining_calls is not None
                    and remaining_calls < 1):
                    sleep_time = reset_time - int(time.time())

                    if sleep_time > 0:
                        log.warning(f"Rate limit reached. Sleeping for: {sleep_time}")

                        time.sleep(sleep_time + 1)

                    try:
                        resp = self.session.request(method, req_url, params=params,
                                                    headers=headers, data=post_data,
                                                    json=json_payload, timeout=self.timeout
                                                    )
                    except Exception as e:
                        raise ValowrapperException(f'Failed to send request: {e}').with_traceback(sys.exc_info()[2])
                    
                    if 200 <= resp.status_code < 300:
                        break

                    rem_calls = resp.headers.get('x-rate-limit-remaining')

                    if rem_calls is not None:
                        remaining_calls = int(rem_calls)
                    elif remaining_calls is not None:
                        remaining_calls -= 1

                    reset_time = resp.headers.get('x-rate-limit-reset')

                    if reset_time is not None:
                        reset_time = int(reset_time)

                    retry_delay = self.retry_delay

                    if resp.status_code in (420, 429) and self.wait_on_rate_limit:
                        if remaining_calls == 0:
                            continue

                        if 'retry-after' in resp.headers:
                            retry_delay = float(resp.headers['retry-after'])

                    elif self.retry_errors and resp.status_code not in self.retry_errors:
                        break

                    time.sleep(retry_delay)
                    retries_performed += 1

                    self.last_response = resp
                    if resp.status_code == 400:
                        raise BadRequest(resp)
                    if resp.status_code == 401:
                        raise Unauthorized(resp)
                    if resp.status_code == 403:
                        raise Forbidden(resp)
                    if resp.status_code == 404:
                        raise NotFound(resp)
                    if resp.status_code == 429:
                        raise TooManyRequests(resp)
                    if resp.status_code >= 500:
                        raise OriginServerError(resp)
                    if resp.status_code and not 200 <= resp.status_code < 300:
                        raise HTTPException(resp)
                    
                    return resp.json()
        finally:
            self.session.close()

    def get_account_details(self, name: str, tag: str, *, force: bool | None = None):
        if force: params = {'force': force}
        else: params = {}
        
        return self.request("GET", f"account/{name}/{tag}", params=params)