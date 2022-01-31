import urllib.parse
from requests import Session
import logging
from singleton_decorator import SingletonDecorator
import settings


@SingletonDecorator
class ApiHandler:

    login_uri = settings.login_uri
    main_uri = settings.main_uri

    headers = {
        'Accept': settings.accept,
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': settings.userAgent
    }

    def __init__(self):
        self.session = Session()
        self.token = None

    def update_blocked_call(self, call_details, call_type, credentials):
        try:
            # first login
            self.__login(user=credentials['user_name'], password=credentials['user_pass'])

            if 'NOT USED' in str(call_type).upper() or 'BOOKED' in str(call_type).upper():
                return self.excuse_call(call_details, call_type)
            else:
                return self.reclassify_call(call_details, call_type)
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            self.token = None
        return False

    def update_blocked_calls(self, calls, credentials):
        # first login
        api_responses = []
        self.__login(user=credentials['user_name'], password=credentials['user_pass'])

        for call in calls:
            report_id = call['id']
            call_id = call['call_id']
            call_type = call['call_type']
            call_details = call['call_details']
            try:

                if 'NOT USED' in str(call_type).upper() or 'BOOKED' in str(call_type).upper():
                    api_responses.append({'id': report_id, 'call_id': call_id,
                                          'response': self.excuse_call(call_details, call_type)})
                else:
                    api_responses.append({'id': report_id, 'call_id': call_id,
                                          'response': self.reclassify_call(call_details, call_type)})
            except Exception as x:
                logging.exception("Exception occurred: %s", x)
            finally:
                self.token = None
        return api_responses

    def reclassify_call(self, call_details, call_type):
        try:
            uri = settings.reclassify
            headers = {
                'accept': 'application/json',
                'content-type': 'application/json',
                'x-requested-with': 'XMLHttpRequest'
            }

            post_data = {"id": call_details['call_id'],
                         "type": call_type,
                         "agentId": call_details['agent_id'],
                         "jobId": call_details['job_id'],
                         "callReasonId": call_details['call_reason_id'],
                         "memo": call_details['call_memo']}

            if self.token is not None:
                headers['x-csrf-token'] = urllib.parse.unquote_plus(self.token)
            response = self.session.post(uri, json=post_data, headers=headers)
            if response.ok:
                return True
        except Exception as x:
            logging.exception("Exception occurred: %s", x)

        return False

    def excuse_call(self, call_details, call_type):
        try:
            logging.info('Excuse call...')
            job_details = self.get_block_details(call_details['blocked_id'])
            logging.debug("Job details: %s", job_details)

            if job_details and len(job_details) > 0 and 'Items' in job_details:
                j_details = job_details['Items'][0]
                job_id = j_details['Id']
                uri = settings.excuse
                headers = {
                    'accept': 'application/json',
                    'content-type': 'application/json',
                    'x-requested-with': 'XMLHttpRequest'
                }

                post_data = {"id": call_details['call_id'],
                             "agentId": call_details['agent_id'],
                             "jobId": job_id}

                if self.token is not None:
                    headers['x-csrf-token'] = urllib.parse.unquote_plus(self.token)
                logging.debug("Headers: %s", headers)
                response = self.session.post(uri, json=post_data, headers=headers)
                logging.debug("Response: %s", response)
                if response.ok:
                    return True
        except Exception as x:
            logging.exception("Exception occurred: %s", x)

        return False

    def get_block_details(self, item_id):
        try:
            uri = '{uri}?filter={id}&page=1'.format(uri=settings.getJobs, id=item_id)
            logging.debug("URL: %s", uri)
            headers = {
                'accept': '*/*',
                'User-Agent': settings.userAgent,
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'st-tenant': settings.tenant,
                'x-requested-with': 'XMLHttpRequest'
            }
            if self.token is not None:
                headers['x-csrf-token'] = urllib.parse.unquote_plus(self.token)
            logging.debug("Headers: %s", headers)
            response = self.session.get(uri, headers=headers)
            logging.debug("Response: %s", response)
            if response.ok:
                return response.json()
        except Exception as x:
            logging.exception("Exception occurred: %s", x)

    def __login(self, user, password):
        try:
            login_headers = {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'x-requested-with': 'XMLHttpRequest',
                'User-Agent': settings.userAgent}

            if self.token is not None:
                login_headers['x-csrf-token'] = urllib.parse.unquote_plus(self.token)

            post_param = {'isPersistent': 'true',
                          'username': user,
                          'password': password}

            logging.debug('Login Param: %s', post_param)

            # fake login try
            response = self.session.post(url=self.login_uri, data=post_param, headers=login_headers)
            if not response.ok:
                return False

            # parse csrf token and login
            rh = response.headers
            self.parse_token(rh)
            if self.token is not None:
                login_headers['x-csrf-token'] = urllib.parse.unquote_plus(self.token)

            response = self.session.post(url=self.login_uri, data=post_param, headers=login_headers)
            if not response.ok:
                return False

            # hit main page to check if logged in successfully or not
            response = self.session.get(self.main_uri, headers=self.headers)
            if not response.ok:
                logging.exception("Response NOT OK. Headers: %s", response.headers)
                return False

            return response.url == self.main_uri
        except Exception as x:
            logging.exception("Exception occurred: %s", x)

    def parse_token(self, rh):
        try:
            cookie = rh['Set-Cookie']
            cl = str(cookie).split(',')
            for c in cl:
                if 'X-CSRF-Token=' in c:
                    t = c.replace('X-CSRF-Token=', '').strip().strip(';')
                    if t != '':
                        ts = t.split(';')
                        if ts and len(ts) > 0:
                            self.token = ts[0].strip()
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
