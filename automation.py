# -*- coding: utf-8 -*-

import csv
import ftplib
import json
import logging
import os
import sys
import threading
import urllib.parse
import boto3
import requests
import settings
from botocore.exceptions import ClientError

import settings
from models import DbHandler
from datetime import datetime, timedelta


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


class Automation:
    headers = {
        'Accept': settings.accept,
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': settings.userAgent
    }

    login_uri = settings.login_uri
    main_uri = settings.main_uri
    record_uri = settings.record_uri
    token = None
    session = requests.Session()

    def __init__(self, *args):
        self.user_name = args[0]
        self.user = args[1]
        self.pwd = args[2]
        if len(args) > 3:
            self.stv_report_uri = args[3]
        if len(args) > 4:
            self.sta_scorecard = args[4]
        if len(args) > 5:
            self.tpa_report_uri = args[5]
        if len(args) > 6:
            self.tpa_scorecard = args[6]
        if len(args) > 7:
            self.blocked_call_job_id = args[7]
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
        del self

    def __login(self):
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
                          'password': self.pwd,
                          'username': self.user}

            logging.info('Login Param: %s', post_param)
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
                logging.warning("Headers: %s", response.headers)
                return False

            return response.url == self.main_uri
        except Exception as x:
            logging.exception(x)

    def __get_report(self, report_id, report_type):
        try:
            headers = {
                'accept': 'application/json',
                'content-type': 'application/json',
                'origin': settings.main_uri,
                'referer': "{}/".format(settings.main_uri),
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-Agent': settings.userAgent,
            }

            report_uri = '{}?id={}&dataSource=Calls&updateReportRunHistory=true'.format(settings.query_uri, report_id.strip())
            dt_from = (datetime.now() - timedelta(1)).strftime('%Y-%m-%d')
            dt_to = (datetime.now() + timedelta(1)).strftime('%Y-%m-%d')
            post_data = {"FilterBy": "0",
                         "RecipientId": "",
                         "From": dt_from,
                         "To": dt_to,
                         "VisibleFields": "CallId,CallDate,Name,CallCampaign,Direction,Duration,CallType,CallMemo,CallReason,CallTime,CallerPhoneNumber,JobId,JobType,CustomerName",
                         "Fields": "CallId,CallDate,Name,CallCampaign,Direction,Duration,CallType,CallMemo,CallReason,CallTime,CallerPhoneNumber,JobId,JobType,CustomerName"}

            # print(json.dumps(post_data, indent=4))

            headers['x-requested-with'] = 'XMLHttpRequest'
            if self.token is not None:
                headers['x-csrf-token'] = urllib.parse.unquote_plus(self.token)
            # print(headers)

            logging.info('Report uri: %s', report_uri)
            response = self.session.post(url=report_uri, json=post_data, headers=headers)
            # print(response)
            if response.ok:
                # print(response.json())
                self.parse_json(response.json(), report_type)
        except Exception as x:
            logging.exception(x)

    def get_call_details(self, id):
        try:
            response = self.session.get('https://go.servicetitan.com/Call/Detail/{}'.format(id))
            if response.ok:
                logging.info('Call details...........')
                call_details = response.json()
                logging.info("%s", call_details)
                return call_details
        except Exception as x:
            logging.exception(x)

    def parse_json(self, json_data, report_type):
        try:
            logging.info('Total records: %s', len(json_data))
            # return
            for j_data in json_data:
                logging.debug('%s', j_data)
                upload_path = ''
                try:
                    q_data = self.db_handler.search_report({'call_id': j_data['CallId'], 'report_type': report_type})
                    if q_data:
                        logging.warning('Record already exists!')
                        continue

                    headers = {
                        'accept': '*/*',
                        'User-Agent': settings.userAgent,
                        'range': 'bytes=0-',
                        'referer': 'https://go.servicetitan.com/',
                        'sec-fetch-dest': 'audio',
                        'sec-fetch-mode': 'no-cors',
                        'sec-fetch-site': 'same-origin'
                    }
                    r_uri = self.record_uri.format(j_data['CallId'])
                    # print(r_uri)
                    response = self.session.get(r_uri, headers=headers)
                    if response.ok and response.status_code == 206:
                        try:
                            audio_file = './recordings/{}/{}.mp3'.format(self.user, j_data['CallId'])
                            with open(audio_file, 'wb') as f:
                                f.write(response.content)

                            # self.upload_to_ftp(audio_file, j_data['CallId'])
                            upload_path = self.upload_to_amazons3(audio_file, j_data['CallId'])
                        except Exception as wx:
                            logging.exception(wx)
                    else:
                        upload_path = response.text
                        logging.info("%s - %s", response.status_code, response.text)
                        print('{} - {}'.format(response.status_code, response.text))
                except Exception as ex:
                    print(ex)

                # get call details
                call_details = self.get_call_details(j_data['CallId'])

                ## save to database
                self.save_to_db(j_data, call_details, upload_path, report_type)
        except Exception as x:
            logging.exception(x)

    def save_to_db(self, json_data, call_details, upload_path, report_type):
        try:
            data = {
                'call_id': json_data['CallId'],
                'call_date': json_data['CallDate'].split("T")[0],
                'name': json_data['Name'],
                'call_campaign': json_data['CallCampaign'],
                'direction': json_data['Direction'],
                'duration': json_data['Duration'],
                'call_type': json_data['CallType'],
                'call_memo': json_data['CallMemo'],
                'call_reason': json_data['CallReason'],
                'call_time': json_data['CallTime'],
                'caller_phone': json_data['CallerPhoneNumber'].split(", ")[0],
                'job_id': json_data['JobId'],
                'job_type': json_data['JobType'] if 'JobType' in json_data else None,
                'customer_name': json_data['CustomerName'] if 'CustomerName' in json_data else None,
                'url': self.record_uri.format(json_data['CallId'])
            }

            if call_details:
                if 'Status' in call_details:
                    data['status'] = call_details['Status']

                if 'CallReasonId' in call_details:
                    data['call_reason_id'] = call_details['CallReasonId']

                if 'From' in call_details:
                    data['call_from'] = call_details['From']

                if 'To' in call_details:
                    data['call_to'] = call_details['To']

                if 'AgentName' in call_details:
                    data['agent_name'] = call_details['AgentName']

                if 'AgentUserId' in call_details:
                    data['agent_id'] = call_details['AgentUserId']

            data['record_path'] = 's3://callcriteriasingapore/{}'.format(upload_path)
            data['user_name'] = self.user
            data['user_pass'] = self.pwd
            data['report_type'] = report_type
            if report_type == 1:
                data['report_id'] = self.sta_scorecard
            elif report_type == 2:
                data['report_id'] = self.tpa_scorecard
            data['blocked_id'] = None if self.blocked_call_job_id == '' else self.blocked_call_job_id
            self.db_handler.add_report(data)

            if upload_path == '':
                return 

            # update via api
            api_data = {'agent': data['agent_name'] if 'agent_name' in data else None,
                        'agent_group': self.user_name,
                        'call_type': data['call_type'],
                        'campaign': data['call_campaign'],
                        'call_id': data['call_id'],
                        'appname': 'CallSource 3rd Party',  # fixed
                        'audio_link': data['record_path'],
                        'call_date': data['call_date'],
                        'onaws': 1 if upload_path != '' else 0,
                        'phone': data['caller_phone'].split(", ")[0],
                        'scorecard': self.tpa_scorecard,
                        'apikey': 'BD9B96B0-FACC-41AB-A076-499E492AB97A'  # fixed
                        }
            print('Requesting api for call id: {}'.format(data['call_id']))
            self.update_to_api(**api_data)

        except Exception as x:
            logging.exception(x)

    def upload_to_ftp(self, filename, id):
        try:
            print('Trying to connect ftp...')
            with ftplib.FTP_TLS(timeout=10) as ftp:
                ftp.set_pasv(True)
                ftp.connect(settings.FTP_ADDRESS, 21)
                ftp.auth()
                print('Trying to login ftp...')
                # print(ftp.getwelcome())
                resp = ftp.login(user=settings.FTP_USER, passwd=settings.FTP_PASSWORD)
                print(resp)

                ftp.prot_p()
                # ftp.ccc()

                # ftp.prot_p()
                ftp.set_debuglevel(2)

                # ftp.retrlines('LIST')

                # ftp.prot_p()
                # ftp.set_pasv(False)

                # ftp.login(settings.FTP_USER, settings.FTP_PASSWORD)

                c = ftp.cwd('uploads')
                print(c)

                # pw = ftp.pwd()
                # print(pw)

                # print(ftp.dir())

                # ls = ftp.retrlines('LIST')
                # print('ok... {}'.format(ls))
                with open(os.path.abspath(filename), 'rb') as fb:
                    print('fb...')
                    r = self.storbinary(ftp, 'STOR {}.mp3'.format(id), fb, callback=self.ftp_callback)
                    print(r)

                # ftp.storlines('STOR {}'.format(self.user) + '/{}'.format(id) + '.mp3', uploadfile)
        except Exception as x:
            logging.exception(x)

    def storbinary(self, ftp, cmd, fp, blocksize=8192, callback=None, rest=None):
        """Store a file in binary mode.  A new port is created for you.

        Args:
          cmd: A STOR command.
          fp: A file-like object with a read(num_bytes) method.
          blocksize: The maximum data size to read from fp and send over
                     the connection at once.  [default: 8192]
          callback: An optional single parameter callable that is called on
                    each block of data after it is sent.  [default: None]
          rest: Passed to transfercmd().  [default: None]

        Returns:
          The response code.
        """
        ftp.voidcmd('TYPE I')
        with ftp.transfercmd(cmd, rest) as conn:
            while 1:
                buf = fp.read(blocksize)
                if not buf:
                    break
                conn.sendall(buf)
                if callback:
                    callback(buf)
            # # shutdown ssl layer
            # if _SSLSocket is not None and isinstance(conn, _SSLSocket):
            #     conn.unwrap()
        return ftp.voidresp()

    def ftp_callback(self, block):
        print(block)

    def upload_to_amazons3(self, filename, id):
        try:
            print('Uploading to amazon s3......')
            # Upload the file
            s3_client = boto3.client('s3', aws_access_key_id=settings.AMAZON_ACCESS_KEY,
                                     aws_secret_access_key=settings.AMAZON_SECRET_KEY)
            try:
                upload_path = '{}/{}/{}.mp3'.format(settings.AMAZON_OBJECT_ROOT, self.user, id)
                response = s3_client.upload_file(filename,
                                                 settings.AMAZON_BUCKET_NAME,
                                                 # 'uploads/CallSource/uploads/{}.mp3'.format(id),
                                                 upload_path,
                                                 Callback=ProgressPercentage(filename))
                return upload_path
            except ClientError as e:
                print(e)
        except Exception as x:
            logging.exception(x)

    def update_to_api(self, **kwargs):
        try:
            print(kwargs)
            api_url = 'http://app.callcriteria.com/CallCriteriaAPI.svc/json/AddRecord'
            headers = {
                'content-type': 'application/xml',
                'User-Agent': settings.userAgent,
            }
            params = {"appname": kwargs['appname'],
                      "apikey": kwargs['apikey'],
                      "scorecard": kwargs['scorecard']}
            data = """<CallCriteriaAPI.AddRecordData xmlns="http://schemas.datacontract.org/2004/07/">
                        <AGENT>{}</AGENT> 
                        <AGENT_GROUP>{}</AGENT_GROUP> 
                        <CALL_TYPE>{}</CALL_TYPE> 
                        <CAMPAIGN>{}</CAMPAIGN> 
                        <SESSION_ID>{}</SESSION_ID> 
                        <appname>{}</appname> 
                        <audio_link>{}</audio_link> 
                        <call_date>{}</call_date> 
                        <onaws>{}</onaws> 
                        <phone>{}</phone> 
                        <scorecard>{}</scorecard>
                    </CallCriteriaAPI.AddRecordData>""".format(kwargs['agent'],
                                                               kwargs['agent_group'],
                                                               kwargs['call_type'],
                                                               kwargs['campaign'],
                                                               kwargs['call_id'],
                                                               kwargs['appname'],
                                                               kwargs['audio_link'],
                                                               kwargs['call_date'],
                                                               kwargs['onaws'],
                                                               kwargs['phone'],
                                                               kwargs['scorecard'])
            response = self.session.post(api_url, data=data, headers=headers, params=params)
            if response.ok:
                print('{} - {}'.format(response.status_code, response.json()))

        except Exception as x:
            logging.exception(x)

    def process(self):
        if not self.__login():
            return

        print('Login success...')

        if 'http' in self.stv_report_uri:
            print('Processing STV report...')
            report_id = self.stv_report_uri.split('/')[-1]
            self.__get_report(report_id.strip(), 1)

        if 'http' in self.tpa_report_uri:
            print('Processing TPA report...')
            report_id = self.tpa_report_uri.split('/')[-1]
            self.__get_report(report_id.strip(), 2)

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

    def test_api(self):
        data = {'agent': 'Julie Phan',
                'agent_group': 'Southern Coast Services',
                'call_type': 'Excused',
                'campaign': 'Techs',
                'call_id': '2468001',
                'appname': 'CallSource 3rd Party',
                'audio_link': '/audio/Southern Coast Services/2468001.mp3',
                'call_date': '2021-02-25T08:00:00.000Z',
                'onaws': 1,
                'phone': '7547791497',
                'scorecard': 503,
                'apikey': 'BD9B96B0-FACC-41AB-A076-499E492AB97A'
                }
        automation.update_to_api(**data)

    def get_block_details(self, id):
        try:
            self.__login()
            # uri = 'https://go.servicetitan.com/Call/GetJobs?filter=91690'
            uri = 'https://go.servicetitan.com/Call/GetJobs?filter={}&page=1'.format(id)
            print(uri)
            headers = {
                'accept': '*/*',
                'User-Agent': settings.userAgent,
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'st-tenant': 'canogaparkheatingairconditioning',
                'x-requested-with': 'XMLHttpRequest'
            }
            if self.token is not None:
                headers['x-csrf-token'] = urllib.parse.unquote_plus(self.token)
            print(headers)
            response = self.session.get(uri, headers=headers)
            print(response)
            if response.ok:
                print(response.json())
        except Exception as x:
            logging.exception(x)


if __name__ == '__main__':
    i = 0
    with open('misc/input.csv', 'r+') as f:
        reader = csv.reader(f)
        for r in reader:
            if i == 0:
                i += 1
                continue

            print(r)
            with Automation(*r) as automation:
                # automation.test_api()
                # automation.test()
                automation.process()
                # automation.upload_to_amazons3('recordings/19999771.mp3', 100)
                # automation.upload_to_ftp('./recordings/20006201.mp3', 100)
                # automation.get_block_details(r[-1])
            break
