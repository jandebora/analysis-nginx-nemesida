import argparse
from pwn import log
import time
from datetime import datetime
import re

# Constant variables
DESCRIPTION = "Script that parses Nemesida log file and generates a .index file recovering necessary \
    information to the research."
REQUIRED_ARGS = "required arguments"

LOG_ARG = "-l"
LOG_DEFAULT = "/var/log/nginx/error.log"
LOG_HELP = "Nginx error log file which contains information about Nemesida blocked urls. By default: %s" \
    % LOG_DEFAULT
LOG_VARIABLE_NAME = "error_log"

ACCESS_LOG_ARG = "-a"
ACCESS_LOG_DEFAULT = "/var/log/nginx/access.log"
ACCESS_LOG_HELP = "Nginx access log file which contains information about access to the server. By default: %s" \
     % ACCESS_LOG_DEFAULT
ACCESS_LOG_VARIABLE_NAME = "access_log"

LOG_INFO_MAIN = "Analyzing logs..."
FILE_NOT_EXISTS_ERROR = "File %s does not exist"
OUTPUT_FILE_NAME = "analysis-%s.index"

# Functions
def get_access_log_compiled_pattern():
    return re.compile(r'\[(?P<timestamp>\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] '
        r'\"GET (?P<uri>.+) HTTP\/1\.1\" '
        r'(?P<http_message>\d{3}) .+ '
        r'"request_id\":\"(?P<id>[a-zA-Z0-9]+)\"'
        )

# Init parser parameters
parser = argparse.ArgumentParser(description=DESCRIPTION)
# requiredArguments = parser.add_argument_group(REQUIRED_ARGS)
parser.add_argument(LOG_ARG, help=LOG_HELP, default=LOG_DEFAULT, metavar=LOG_VARIABLE_NAME, dest=LOG_VARIABLE_NAME)
parser.add_argument(ACCESS_LOG_ARG, help=ACCESS_LOG_HELP, default=ACCESS_LOG_DEFAULT, \
    metavar=ACCESS_LOG_VARIABLE_NAME, dest=ACCESS_LOG_VARIABLE_NAME)
args = parser.parse_args()

# Main
time_launch = int(datetime.timestamp(datetime.now()))
output_file_name = OUTPUT_FILE_NAME % time_launch

prueba = '2021/08/16 17:59:59 [error] 677#677: *13245412 Nemesida WAF: the request f6a62ce7e9d04e0e9a96b2322a03379d blocked by rule ID 1559 in zone URL, client: 172.19.0.1, server: localhost, request: "GET /etc/passwd%2500%26Action%3Dblast%26hidenav%3D1%0A HTTP/1.1", host: "localhost"'
prueba2 = '172.19.0.1 - - [17/Aug/2021:19:27:10 +0200] "GET /wp-admin/admin-ajax.php/%3Fsrch_txt%3D%27or%25201%3D1--%2520%26action%3Dthe_search_text%0A HTTP/1.1" 403 153 "-" "python-requests/2.26.0" "-" "request_id":"e90f9480d500cad488650afb3a73c854"'

# rule_id_pattern = r'rule ID (?P<id>\d+)'
# request_id_pattern_error_log = r'the request (?P<id>[a-zA-Z0-9]+)'

access_pattern = get_access_log_compiled_pattern()
# result = re.search(access_log_pattern, prueba2)
result = access_pattern.search(prueba2)
print("Timestamp: {}\nUri: {}\nHTTP Message: {}\nRequest ID: {}".format(result.group('timestamp'), result.group('uri'), result.group('http_message'), result.group('id')))

log.info(LOG_INFO_MAIN)
try:
    #file_out = open(output_file_name, 'a')
    with open(args.access_log, encoding='ISO-8859-1', errors='ignore') as log_file:
        count = 0
        count403 = 0
        count_no_403 = 0
        for line in log_file:
            result = access_pattern.search(line)
            if result.group('http_message') == '403':
                count403 += 1
            else:
                count_no_403 += 1
            count +=1
        print(count)
        print(count403)
        print(count_no_403)
        print(str(count403 + count_no_403))
    log_file.close()
    #file_out.close()
except FileNotFoundError:
    log.error(FILE_NOT_EXISTS_ERROR)