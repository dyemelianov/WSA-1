import os

# Maintain Docker connection to MongoDB
DB_HOST = 'host.docker.internal' if os.environ.get('STAGE', False) else 'localhost'
DB_PORT = '3306'
DB_USERNAME = 'root'
DB_PASSWORD = 'DB_PASSWORD'
DB_NAME = 'DB_NAME'

# Selenium container
SELENIUM_URI = 'host.docker.internal'

# FTP credentials
FTP_ADDRESS = 'FTP_ADDRESS'
FTP_USER = 'FTP_USER'
FTP_PASSWORD = 'FTP_PASSWORD'

# Input configuration
INPUT_FILE = 'INPUT_FILE.csv'
INPUT_BAK_FOLDER = 'INPUT_BAK_FOLDER'

# Amazon s3 credential
AMAZON_ACCESS_KEY = 'AMAZON_ACCESS_KEY'
AMAZON_SECRET_KEY = 'AMAZON_SECRET_KEY'
AMAZON_BUCKET_NAME = 'AMAZON_BUCKET_NAME'
AMAZON_OBJECT_ROOT = 'audio/AMAZON_OBJECT_ROOT'

# Script config
SLEEP_TIME = 5 * 60
START_HOUR = 0
END_HOUR = 22

TIMEOUT = 120
FAKE_TIMEOUT = 20

# Scorecard timespans in a seconds
TIMESPAN_A = 24 * 60 * 60
TIMESPAN_B = 30 * 60
TIMESPAN_SLEEP = 10 * 60

TIME_FORMAT = "%m/%d/%Y, %H:%M:%S"
REPORT_FIELDS = ["CallId", "CallDate", "Name", "CallCampaign", "Direction", "Duration", "CallType", "CallMemo",
          "CallReason", "CallTime", "CallerPhoneNumber", "JobId", "JobType", "CustomerName"]


login_uri = 'https://up.caller.com/Auth/Login'
main_uri = 'https://up.caller.com/'
reclassify = 'https://up.caller.com/Call/Reclassify'
excuse = 'https://up.caller.com/Call/Excuse'
getJobs = 'https://up.caller.com/Call/GetJobs'
details = 'https://up.caller.com/Call/Detail/{}'
api_uri = 'http://app.Samurai.com/SamuraiAPI.svc/json/AddRecord'

login_new = 'https://up.caller.com/auth/newauth/login'

record_uri = 'https://up.caller.com/Call/CallRecording/{}'
query_uri = 'https://up.caller.com/app/api/reporting/CustomReport/QueryReportData'

userAgent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36'
accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
tenant = 'canogaparkheatingairconditioning'

report_a = '123'
report_b = '456'

api_key = 'api_key'
