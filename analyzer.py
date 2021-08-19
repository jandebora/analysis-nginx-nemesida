import argparse
from pwn import log
from datetime import datetime
import re
from urllib import parse

# Constant variables
DESCRIPTION = "Script that parses Nemesida log files and generates a .index and .clean files recovering necessary \
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

INFO_MAIN = "Starting analysis..."
START_ACCESS_LOG = "Analyzing access log..."
FILE_NOT_EXISTS_ERROR = "File %s does not exist"
DETECTED = "Detected URIs by Nemesida"
UNDETECTED = "Undetected URIs by Nemesida"
ANALYSIS_INDEX_FILE = "analysis-%s.index"
ANALYSIS_CLEAN_NAME = "analysis-%s.clean"
ANALYSIS_FILE_LOG_START = "Starting analysis for {} file"
ANALYSIS_FILE_LOG_END = "Analysis finished for {} file"
FILES_GENERATED = "Files {} and {} generated"
ANALYSIS_ERROR_END_START = "File {} modified"
END_MAIN = "Analysis completed successfully"

INDEX_FILE_LINE = "{}\tUri {}\tRequestID {}\tNattacks\n"
CLEAN_FILE_LINE = "{}\n"

# Functions
def init_parser():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    # requiredArguments = parser.add_argument_group(REQUIRED_ARGS)
    parser.add_argument(LOG_ARG, help=LOG_HELP, default=LOG_DEFAULT, metavar=LOG_VARIABLE_NAME, dest=LOG_VARIABLE_NAME)
    parser.add_argument(ACCESS_LOG_ARG, help=ACCESS_LOG_HELP, default=ACCESS_LOG_DEFAULT, \
        metavar=ACCESS_LOG_VARIABLE_NAME, dest=ACCESS_LOG_VARIABLE_NAME)
    return parser.parse_args()

def get_access_log_compiled_pattern():
    return re.compile(r'(?P<timestamp>\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\]) '
        r'\"GET (?P<uri>.+) HTTP\/1\.1\" '
        r'(?P<http_status>\d{3}) .+ '
        r'\"python-requests.+ '
        r'"request_id\":\"(?P<id>[a-zA-Z0-9]+)\"'
        )

def access_log_analysis(access_log_arg, index_file_name, clean_file_name):
    log.info(ANALYSIS_FILE_LOG_START.format(access_log_arg))
    
    access_log_cp = get_access_log_compiled_pattern()
    detected_uris = log.progress(DETECTED)
    undetected_uris = log.progress(UNDETECTED)
    try:
        clean_file = open(clean_file_name, 'a')
        index_file = open(index_file_name, 'a')
        with open(access_log_arg, encoding='ISO-8859-1', errors='ignore') as log_file:
            detected_count = 0
            undetected_count = 0
            for line in log_file:
                detected_uris.status("%s" % detected_count)
                undetected_uris.status("%s" % undetected_count)
                result = access_log_cp.search(line)
                if result is not None:
                    uri = result.group('uri')
                    decoded_uri = parse.unquote(uri)
                    if result.group('http_status') == '403':
                        timestamp = result.group('timestamp')
                        request_id = result.group('id')
                        index_file.write(INDEX_FILE_LINE.format(timestamp, decoded_uri, request_id))
                        detected_count += 1
                    else:
                        clean_file.write(CLEAN_FILE_LINE.format(decoded_uri))
                        undetected_count += 1
        log_file.close()
        clean_file.close()
        index_file.close()

        log.info(ANALYSIS_FILE_LOG_END.format(access_log_arg))
        log.info(FILES_GENERATED.format(index_file_name, clean_file_name))
    except FileNotFoundError:
        log.error(FILE_NOT_EXISTS_ERROR)

# Main
args = init_parser()
time_launch = int(datetime.timestamp(datetime.now()))
index_file_name = ANALYSIS_INDEX_FILE % time_launch
clean_file_name = ANALYSIS_CLEAN_NAME % time_launch

log.info(INFO_MAIN)
access_log_analysis(args.access_log, index_file_name, clean_file_name)
log.info(END_MAIN)