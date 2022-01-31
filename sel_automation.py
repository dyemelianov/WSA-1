# -*- coding: utf-8 -*-

import csv
import datetime
import json
import os
import platform
import sys
import threading
import time
import urllib.parse

import boto3
import logging
import requests
from botocore.exceptions import ClientError
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from tqdm import tqdm

import fields
import settings
from api_handler import ApiHandler
from models import DbHandler, to_dict

time_format = settings.TIME_FORMAT


class ProgressPercentage(object):
    def __init__(self, filename):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        # To simplify, assume this is hooked up to a single filename
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._size) * 100
            sys.stdout.write(
                "\r%s  %s / %s  (%.2f%%)" % (
                    self._filename, self._seen_so_far, self._size,
                    percentage))
            sys.stdout.flush()


class SelAutomation:
    headers = {
        'Accept': settings.accept,
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': settings.userAgent
    }

    login_uri = settings.login_new
    main_uri = settings.main_uri
    record_uri = settings.record_uri
    token = None
    session = requests.Session()

    def __init__(self, *args):
        self.driver = None
        self.agent_group = args[0]
        self.user = args[1]
        self.pwd = args[2]
        if len(args) > 3:
            self.api_key = args[3]
        if len(args) > 4:
            self.scorecard = args[4]
        if len(args) > 5:
            self.report_uri = args[5]
        if len(args) > 6:
            self.blocked_call_job_id = args[6]
        else:
            self.blocked_call_job_id = None

    def __enter__(self):
        try:
            record_path = './recordings/{}'.format(self.user)
            if not os.path.exists(record_path):
                os.mkdir(record_path)
        except Exception as x:
            logging.exception(x)

        self.db_handler = DbHandler()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.driver:
            self.driver.close()
        del self

    def __login(self):
        """
        Login User
        """
        try:
            chrome_options = Options()
            operating_sys = platform.system()

            if operating_sys.startswith('Linux'):
                if os.environ.get('STAGE', False):
                    self.driver = webdriver.Chrome('chromedriver_linux64/chromedriver', options=chrome_options)
                else:
                    self.driver = webdriver.Remote(f"http://{settings.SELENIUM_URI}:4444/wd/hub",
                                                   DesiredCapabilities.CHROME)
            elif operating_sys.startswith('Win'):
                if os.environ.get('STAGE', False):
                    self.driver = webdriver.Chrome('chromedriver_windows/chromedriver', options=chrome_options)
                else:
                    self.driver = webdriver.Remote(f"http://{settings.SELENIUM_URI}:4444/wd/hub",
                                                   DesiredCapabilities.CHROME)

            self.driver.get(self.login_uri)

            # fill up user and password
            user_input = self.driver.find_element_by_name("username")
            user_input.send_keys(self.user)

            pass_input = self.driver.find_element_by_name("password")
            pass_input.send_keys(self.pwd)

            self.driver.find_element_by_xpath('//button[@type="submit"]').click()

            timeout = settings.TIMEOUT
            try:
                element_present = EC.url_contains('{}#/new/dashboards/modular-dashboard'.format(settings.main_uri))
                WebDriverWait(self.driver, timeout).until(element_present)
                logging.info("Log in success")
                login_id = self.db_handler.add_login({"agent_group": self.agent_group})
                logging.debug("Login id: %s", login_id)
                return True
            except TimeoutException:
                logging.exception("Timed out waiting for page to load")
        except Exception as x:
            logging.exception(x)

        return False

    def __process_queue(self):
        """Update items from queue"""
        api_response = []
        try:
            records = self.db_handler.search_queue({"agent_group": self.agent_group, "state": "New"})
            if records:
                calls = []

                for record in records:
                    data = self.db_handler.search_report({'call_id': record.call_id})
                    data_dict = to_dict(data)
                    calls.append({'id': record.id, 'call_id': record.call_id, 'call_details': data_dict,
                                  'call_type': record.call_type})

                credentials = {'user_name': self.user, 'user_pass': self.pwd}
                api_responses = ApiHandler().update_blocked_calls(calls, credentials)
                for response in api_responses:
                    if api_responses:
                        self.db_handler.update_queue_by_id(response['id'], {"state": "Done"})
                        logging.info("Queue processed: %s", api_responses)
        except Exception as ex:
            logging.exception("Failed to process queue: %s", ex)
        # return

    def __get_report(self, report_uri, report_type):
        """
        Get report
        """
        # TODO: make sure if possible to refactor on HTTP, instead of Selenium
        report_id = report_uri.split("/")[-1]
        logging.debug("Report id: %s", report_id)

        try:
            self.driver.get(report_uri)
            timeout = settings.TIMEOUT
            try:
                logging.info("Fake sleep")
                for iterator in tqdm(range(settings.FAKE_TIMEOUT)):
                    time.sleep(1)
                element_absent = EC.invisibility_of_element((By.XPATH, '//*[@id="global-loading"]'))
                WebDriverWait(self.driver, timeout).until(element_absent)
                logging.info('Page loaded')
            except TimeoutException:
                logging.exception("Timed out waiting for page to load")

            cks = []
            cookies = self.driver.get_cookies()
            if cookies and len(cookies) > 0:
                for c in cookies:
                    cks.append('{}={}'.format(c['name'], c['value']))
            cookie = '; '.join(cks)

            dt = self.driver.find_element_by_xpath('//button[contains(.,"Run Report")]')

            calls_response = self.get_report_request(report_id, cookie)
            calls = json.loads(calls_response)
            if calls:
                self.get_response_results(calls, report_type, cookie)

        except Exception as x:
            logging.exception(x)

    def get_response_results(self, calls, report_type, cookie):
        """Process table of report. Extract data"""
        try:
            report_fields = settings.REPORT_FIELDS
            for call in calls:
                call_details = {}
                for field in report_fields:
                    call_details[field] = call[field]
                # parse call details by id
                self.parse_call_details(call_details, report_type, cookie=cookie)
        except Exception as x:
            logging.exception(x)

    def get_search_results(self, report_type, cookie):
        """Process table of report. Extract data"""
        try:
            timeout = settings.TIMEOUT
            element = None
            try:
                time.sleep(settings.FAKE_TIMEOUT)
                element_present = EC.presence_of_element_located(
                    (By.XPATH, '//table[@class="k-grid-table"]'))
                element = WebDriverWait(self.driver, timeout).until(element_present)
                logging.info("Page loaded")
            except TimeoutException:
                logging.exception("Timed out waiting for page to load")

            src = element.get_attribute('outerHTML')
            soup = BeautifulSoup(src, 'html5lib')
            tr_list = soup.find_all('tr')
            logging.info('Total records found on current page: %s', len(tr_list))

            for tr in tr_list[:-1]:
                td_list = tr.find_all('td')
                if len(td_list) == 0:
                    continue

                call_details = {}
                keys = range(2, 16)
                for k in keys:
                    call_details[fields.call_details[k]] = td_list[k].text.strip()

                # parse call details by id
                self.parse_call_details(call_details, report_type, cookie=cookie)
        except Exception as x:
            logging.exception(x)

    def parse_call_details(self, j_data, report_type, cookie):
        """Upload call to Amazon"""
        """
        Parsing call details.
        Upload file to Amazon.

        :param j_data:
        :type j_data:
        :param report_type:
        :type report_type:
        :param cookie:
        :type cookie:
        :return:
        :rtype:
        """
        upload_path = ''
        try:
            q_data = self.db_handler.search_report({'call_id': j_data[fields.call_details[2]]})
            if q_data:
                logging.info('Record %s already exists!', j_data[fields.call_details[2]])
                return

            headers = {
                'accept': '*/*',
                'User-Agent': settings.userAgent,
                'range': 'bytes=0-',
                'referer': "{}/".format(settings.main_uri),
                'sec-fetch-dest': 'audio',
                'sec-fetch-mode': 'no-cors',
                'sec-fetch-site': 'same-origin',
                'cookie': cookie
            }
            r_uri = self.record_uri.format(j_data[fields.call_details[2]])
            logging.info('Call uri: %s', r_uri)
            response = self.session.get(r_uri, headers=headers)
            if response.ok and response.status_code == 206:
                try:
                    audio_file = './recordings/{}/{}.mp3'.format(self.user, j_data[fields.call_details[2]])
                    with open(audio_file, 'wb') as f:
                        f.write(response.content)

                    # upload to amazon s3
                    upload_path = self.upload_to_amazons3(audio_file, j_data[fields.call_details[2]])
                except Exception as wx:
                    logging.exception(wx)
            else:
                upload_path = response.text
                logging.info("Status code: %s, text: %s", response.status_code, response.text)

            # get call details
            call_details = self.get_call_details(j_data[fields.call_details[2]], cookie)
            logging.info("Call details: %s", call_details)

            # save to database
            self.save_to_db(j_data, call_details, upload_path, report_type)
        except Exception as ex:
            logging.exception(ex)

    def get_call_details(self, call_id, cookie):
        try:
            headers = {
                'accept': '*/*',
                'User-Agent': settings.userAgent,
                'cookie': cookie
            }
            details_uri = settings.details.format(call_id)
            logging.debug("Details URL: %s", details_uri)
            response = self.session.get(details_uri, headers=headers)
            if response.ok:
                logging.info('Call details...........')
                call_details = response.json()
                return call_details
        except Exception as x:
            logging.exception(x)

    def save_to_db(self, json_data, call_details, upload_path, report_type):
        try:
            print('Upload path: {}'.format(upload_path))
            record_found = True
            if not upload_path or \
                    upload_path == '' or \
                    '{}.mp3'.format(json_data[fields.call_details[2]]) not in upload_path:
                logging.warning('No record found so skip call api...')
                # TODO: add processing for the records without files
                record_found = False

            data = fields.map_json_fields(self.agent_group, self.record_uri, json_data, record_found)

            fields.map_call_details(call_details, data)

            data['record_path'] = '/{}'.format(upload_path) if record_found else '{}'.format(upload_path)
            data['user_name'] = self.user
            data['user_pass'] = self.pwd
            data['report_type'] = report_type
            data['report_id'] = self.scorecard
            data['blocked_id'] = None if self.blocked_call_job_id == '' else self.blocked_call_job_id

            # update via api
            api_data = fields.map_api_data(data, record_found)
            logging.debug("Agent group: %s, scorecard: %s", api_data['agent_group'], api_data['scorecard'])
            print(f'Requesting api for call id: {data["call_id"]}')
            if record_found:
                if self.update_to_api(**api_data):
                    self.db_handler.add_report(data)
            else:
                self.db_handler.add_report(data)
                logging.warning("SKIPPING API CALL")
        except Exception as x:
            logging.exception(x)

    def upload_to_amazons3(self, filename, call_id):
        try:
            logging.info('Uploading to amazon s3......')
            # Upload the file
            s3_client = boto3.client('s3', aws_access_key_id=settings.AMAZON_ACCESS_KEY,
                                     aws_secret_access_key=settings.AMAZON_SECRET_KEY)
            try:
                upload_path = '{}/{}/{}.mp3'.format(settings.AMAZON_OBJECT_ROOT, self.user, call_id)
                response = s3_client.upload_file(filename,
                                                 settings.AMAZON_BUCKET_NAME,
                                                 upload_path,
                                                 Callback=ProgressPercentage(filename))
                return upload_path
            except ClientError as e:
                logging.exception(e)
        except Exception as x:
            logging.exception(x)

    def update_to_api(self, **kwargs):
        try:
            logging.debug(kwargs)
            api_url = settings.api_uri
            headers = {
                'content-type': 'application/xml',
                'User-Agent': settings.userAgent,
            }
            params = {"appname": kwargs['appname'],
                      "apikey": kwargs['apikey'],
                      "scorecard": kwargs['scorecard']}
            data = fields.map_data(kwargs)
            response = self.session.post(api_url, data=data, headers=headers, params=params)
            if response.ok:
                logging.info("Status code: %s, response: %s", response.status_code, response.json())
                return True
        except Exception as x:
            logging.exception(x)

        return False

    def process(self):
        """Report types branching is controlled here."""
        time_span = 0
        if self.scorecard == settings.report_a:
            time_span = settings.TIMESPAN_A
        elif self.scorecard == settings.report_b:
            time_span = settings.TIMESPAN_B

        logins_count = self.db_handler.search_login({"agent_group": self.agent_group}, time_span)
        if logins_count == 0 or logins_count is None:
            logging.debug("Agent group: %s - %s", self.agent_group, logins_count)
            if not self.__login():
                return

            logging.info("Login success...")

            if 'http' in self.report_uri:
                report_type = 0
                if self.scorecard == settings.report_a:
                    report_type = 1
                    logging.info('Processing A report...')
                elif self.scorecard == settings.report_b:
                    report_type = 2
                    logging.info('Processing B report...')
                self.__get_report(self.report_uri, report_type)

                self.__process_queue()

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
            logging.exception(x)

    def get_block_details(self, id):
        """Not in use
        """
        # TODO: investigate what is it for
        try:
            self.__login()
            uri = '{}?filter={}&page=1'.format(settings.getJobs, id)
            logging.info("URL: %s", uri)
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
            response = self.session.get(uri, headers=headers)
            if response.ok:
                logging.debug("Response OK")
        except Exception as x:
            logging.exception(x)

    def get_report_request(self, report_id, cookie):
        fields = settings.REPORT_FIELDS
        query_uri = settings.query_uri
        try:
            # self.__login()
            uri = f"{query_uri}?id={report_id}&dataSource=Calls&updateReportRunHistory=true"
            logging.info("URL: %s", uri)
            to_date = datetime.datetime.now()
            delta = datetime.timedelta(days=7)
            from_date = to_date - delta
            payload = json.dumps({
                "FilterBy": "0",
                "RecipientId": "",
                "From": from_date.strftime("%Y-%m-%d"),
                "To": to_date.strftime("%Y-%m-%d"),
                "VisibleFields": ",".join(fields),
                "Fields": ",".join(fields)
            })

            headers = {
                'accept': 'application/json',
                'User-Agent': settings.userAgent,
                'x-requested-with': 'XMLHttpRequest',
                'cookie': cookie
            }
            if self.token is not None:
                headers['x-csrf-token'] = urllib.parse.unquote_plus(self.token)
            response = requests.request("POST", uri, headers=headers, data=payload)
            return response.text

        except Exception as x:
            logging.exception(x)


if __name__ == '__main__':
    i = 0

    with open(settings.INPUT_FILE, 'r+') as f:
        reader = csv.reader(f)
        for r in reader:
            if i == 0:
                i += 1
                continue
            logging.info(r)
            with SelAutomation(*r) as automation:
                automation.process()
            break
