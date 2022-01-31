# from datetime import datetime
import csv
import datetime
import json
import logging
import logging.config
import os
import time
from shutil import copyfile
from threading import Thread

import pandas as pd
import xmltodict
from flask import Flask, request, jsonify, render_template
from pytz import timezone, utc

import settings
from api_handler import ApiHandler
from models import DbHandler, to_dict
from sel_automation import SelAutomation

logging.config.fileConfig('logging.conf')

# create logger
logger = logging.getLogger('app.py')

app = Flask(__name__)
db = DbHandler()
# Debugging switch to prevent starting scraping
scraping = True


def get_pst_time():
    date = datetime.datetime.now(tz=utc)
    date = date.astimezone(timezone('US/Pacific'))
    return date.time()


def is_time_between(begin_time, end_time):
    # If check time is not given, default to current UTC time
    check_time = get_pst_time()
    if begin_time < end_time:
        return begin_time <= check_time <= end_time
    else:  # crosses midnight
        return check_time >= begin_time or check_time <= end_time


def backup_file(input_file, to_folder):
    suffix = datetime.datetime.now(tz=utc).strftime("%Y%m%d-%H%M%S")
    file_name = os.path.splitext(input_file)[0]
    file_ext = os.path.splitext(input_file)[1]
    bak_path = f'{to_folder}/{file_name}_{suffix}{file_ext}'
    copyfile(input_file, bak_path)
    logging.info("Backed up input file to: %s", bak_path)


def start_script():
    while True:
        if not is_time_between(datetime.time(hour=settings.START_HOUR), datetime.time(hour=settings.END_HOUR)):
            logger.info('Going to sleep!')
            time.sleep(settings.SLEEP_TIME)

        i = 0
        with open(settings.INPUT_FILE, 'r+') as f:
            reader = csv.reader(f)
            for r in reader:
                if i == 0:
                    i += 1
                    continue

                with SelAutomation(*r) as automation:
                    automation.process()
        logger.info('Going to delayed sleep!')
        time.sleep(settings.TIMESPAN_SLEEP)


@app.route('/calls/update', methods=['POST'])
def update_call():
    data = request.get_data()
    print(data)

    xml = xmltodict.parse(data)
    call = xml['call']
    if 'call_id' not in call:
        return jsonify({'message': 'NO CALL ID SPECIFIED!', 'status': False})

    call_id = call['call_id']
    status = db.update_report_by_id(int(call_id), call)

    return jsonify(status)


@app.route('/test', methods=['GET'])
def test_ping():
    return jsonify({'success': True})


@app.route('/input/edit', methods=['GET', 'POST'])
def my_form_post():
    if request.method == 'POST':
        input_days = request.form['text_box']
        logger.info('Input days: %s', input_days)
        backup_file(settings.INPUT_FILE, settings.INPUT_BAK_FOLDER)
        with open(settings.INPUT_FILE, 'w', newline='') as f:
            f.write(input_days)
            return render_template('index.html', days=input_days)

    if request.method == 'GET':
        value = open(settings.INPUT_FILE, "r").read()
        return render_template('index.html', days=value)


@app.route('/input', methods=['GET'])
def list_input():
    """
    Array of inputs from input file

    :return: Array of inputs
    :rtype: JSON
    """
    df = pd.read_csv(settings.INPUT_FILE, dtype={"Scorecard ID": str, "Booked Call Job ID": str})
    df_json = df.to_json(orient="index")
    parsed = json.loads(df_json)
    json_response = json.dumps(parsed, indent=4)
    response = app.response_class(
        response=json_response,
        status=200,
        mimetype='application/json'
    )
    return response


@app.route('/input/add', methods=['POST'])
def add_input():
    """
    Add the record to input.
    :return: Result
    :rtype: JSON
    """
    data = request.get_data()
    df_json = pd.read_json(data, orient='index')
    df_source = pd.read_csv(settings.INPUT_FILE, dtype={"Scorecard ID": str, "Booked Call Job ID": str})
    backup_file(settings.INPUT_FILE, settings.INPUT_BAK_FOLDER)
    df_final = df_source.append(df_json, ignore_index=True)
    df_final.to_csv(settings.INPUT_FILE, index=None)
    return jsonify({'success': True})


@app.route('/input/replace', methods=['POST'])
def replace_input():
    """
    Add the record to input.
    :return: Result
    :rtype: JSON
    """
    data = request.get_data()
    df_json = pd.read_json(data, orient='records', dtype={"Scorecard ID": int, "Booked Call Job ID": int})
    columns = ["Agent Group", "Username", "Password", "API Key", "Scorecard ID", "Report URL", "Booked Call Job ID"]
    backup_file(settings.INPUT_FILE, settings.INPUT_BAK_FOLDER)
    df_json.fillna("")
    df_json.to_csv(settings.INPUT_FILE, index=None, columns=columns, na_rep="")
    return jsonify({'success': True})


@app.route('/input/delete', methods=['DELETE'])
def delete_input():
    """
    Delete the record from inputs. Sample JSON body:
    [0,2]
    :return: Result
    :rtype: JSON
    """
    data = request.get_data()
    json_data = json.loads(data)
    df_source = pd.read_csv(settings.INPUT_FILE, dtype={"Scorecard ID": str, "Booked Call Job ID": str})
    # print(df_source)
    backup_file(settings.INPUT_FILE, settings.INPUT_BAK_FOLDER)
    df_final = df_source.drop(json_data)
    df_final.to_csv(settings.INPUT_FILE, index=None)
    return jsonify({'success': True})


@app.route('/records/queue', methods=['POST'])
def add_queue_record():
    response = None
    try:
        data = request.get_data()

        json_data = json.loads(data)
        data = db.search_report({'call_id': json_data['call_id']})
        if data:
            data_dict = to_dict(data)
            logger.info('Queue += %s', json_data["agent_group"])
            db.add_queue(json_data)

    except Exception as ex:
        return jsonify({'status': 'FAILED', 'message': '{}'.format(ex)})

    return jsonify({'success': True, 'message': 'done'})


@app.route('/records/update', methods=['POST'])
def update_call_record():
    response = None
    try:
        data = request.get_data()
        print(data)

        json_data = json.loads(data)
        print(json_data)
        data = db.search_report({'call_id': json_data['call_id']})
        if data:
            data_dict = to_dict(data)
            credentials = get_credentials(json_data['agent_group'])
            api_response = ApiHandler().update_blocked_call(data_dict, json_data['call_type'], credentials)
            if api_response:
                return jsonify({'success': True, 'message': 'SUCCESS'})
    except Exception as ex:
        return jsonify({'status': 'FAILED', 'message': '{}'.format(ex)})

    return jsonify({'success': True, 'message': api_response})


def get_credentials(agent_group):
    with open(settings.INPUT_FILE) as f:
        reader = csv.reader(f)
        d = dict()
        for row in reader:
            if row[0] == agent_group:
                d['user_name'] = row[1]
                d['user_pass'] = row[2]
                return d
        return None


if __name__ == '__main__':
    try:
        if scraping:
            # start_script()
            t = Thread(target=start_script)
            t.daemon = True
            t.start()

        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as x:
        logging.exception(x)
