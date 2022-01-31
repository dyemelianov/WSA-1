call_details = ["",
                "",
                "CallId",
                "CallDate",
                "Name",
                "CallCampaign",
                "Direction",
                "Duration",
                "CallType",
                "CallMemo",
                "CallReason",
                "CallTime",
                "CallerPhoneNumber",
                "JobId",
                "JobType",
                "CustomerName"]

mapping = ['call_id',
           'call_date',
           'name',
           'call_campaign',
           'direction',
           'duration',
           'call_type',
           'call_memo',
           'call_reason',
           'call_time',
           'agent_group',
           'caller_phone',
           'job_type',
           'customer_name',
           'url',
           'record_found',
           'agent']


def map_api_data(self, data, record_found):
    api_data = {'agent': data['agent_name'] if 'agent_name' in data else None,
                'agent_group': self.agent_group,
                'call_type': data['call_type'],
                'campaign': data['call_campaign'],
                'call_id': data['call_id'],
                'appname': 'Company 3rd Party',  # fixed
                'audio_link': data['record_path'],
                'call_date': data['call_date'],
                'onaws': 1 if record_found else 0,
                'phone': data['caller_phone'].split(", ")[0],
                'scorecard': data['report_id'],
                'apikey': settings.api_key  # fixed
                }
    return api_data


def map_call_details(call_details_map, data):
    if call_details_map:
        if 'Status' in call_details_map:
            data['status'] = call_details_map['Status']

        if 'CallReasonId' in call_details_map:
            data['call_reason_id'] = call_details_map['CallReasonId']

        if 'From' in call_details_map:
            data['call_from'] = call_details_map['From']

        if 'To' in call_details_map:
            data['call_to'] = call_details_map['To']

        if 'AgentName' in call_details_map:
            data['agent_name'] = call_details_map['AgentName']

        if 'AgentUserId' in call_details_map:
            data['agent_id'] = call_details_map['AgentUserId']

        if 'JobId' in call_details_map:
            data['job_id'] = call_details_map['JobId']


def map_data(kwargs):
    data = """<CompanyAPI.AddRecordData xmlns="http://schemas.datacontract.org/2004/07/">
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
                </CompanyAPI.AddRecordData>""".format(kwargs['agent'],
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
    return data


def map_json_fields(agent_group, record_uri, json_data, record_found):
    data = {
        mapping[0]: json_data[call_details[2]],
        mapping[1]: json_data[call_details[3]].split("T")[0],  # datetime in ISO format
        mapping[2]: json_data[call_details[4]],
        mapping[3]: json_data[call_details[5]],
        mapping[4]: json_data[call_details[6]],
        mapping[5]: json_data[call_details[7]],
        mapping[6]: json_data[call_details[8]],
        mapping[7]: json_data[call_details[9]],
        mapping[8]: json_data[call_details[10]],
        mapping[9]: json_data[call_details[11]],
        mapping[10]: agent_group,
        mapping[11]: json_data[call_details[12]].split(", ")[0],
        mapping[12]: json_data[call_details[14]] if
        call_details[14] in json_data else None,
        mapping[13]: json_data[call_details[15]] if
        call_details[15] in json_data else None,
        mapping[14]: record_uri.format(json_data[call_details[2]]),
        mapping[15]: 1 if record_found else 0
    }
    return data
