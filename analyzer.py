import argparse
from pwn import log
from datetime import datetime
import re
from urllib import parse
import os.path as path
import fileinput

# Constant variables
DESCRIPTION = "Script that parses Nemesida log files and generates a .index and .clean files recovering necessary \
    information to the research."
REQUIRED_ARGS = "required arguments"

ERROR_LOG_ARG = "-e"
ERROR_LOG_DEFAULT = "/var/log/nginx/error.log"
ERROR_LOG_HELP = "Nginx error log file which contains information about Nemesida blocked urls. By default: %s" \
    % ERROR_LOG_DEFAULT
ERROR_LOG_VARIABLE_NAME = "error_log"

ACCESS_LOG_ARG = "-a"
ACCESS_LOG_DEFAULT = "/var/log/nginx/access.log"
ACCESS_LOG_HELP = "Nginx access log file which contains information about access to the server. By default: %s" \
     % ACCESS_LOG_DEFAULT
ACCESS_LOG_VARIABLE_NAME = "access_log"

IDENTIFIER_LOG_ARG = "-id"
IDENTIFIER_LOG_DEFAULT = int(datetime.timestamp(datetime.now()))
IDENTIFIER_LOG_HELP = "Numeric value added to idenfity generated files. By default is the current timestamp: %s" \
    % IDENTIFIER_LOG_DEFAULT
IDENTIFIER_LOG_VARIABLE_NAME = "id"

INFO_MAIN = "Starting analysis..."
START_ACCESS_LOG = "Analyzing access log..."
FILE_NOT_EXISTS_ERROR = "File %s does not exist"
DETECTED = "Detected URIs by Nemesida"
UNDETECTED = "Undetected URIs by Nemesida"
ADDING_NUMBER_OF_ATTACKS = "Adding number of attacks in {} line"
ANALYSIS_INDEX_FILE = "analysis-%s.index"
ANALYSIS_CLEAN_NAME = "analysis-%s.clean"
ANALYSIS_FILE_LOG_START = "Starting analysis for {} file"
ANALYSIS_FILE_LOG_END = "Analysis finished for {} file"
FILES_GENERATED = "Files {} and {} generated"
ANALYSIS_ERROR_END_START = "Added number of attacks to file {}"
END_MAIN = "Analysis completed successfully"

INDEX_FILE_LINE = "{}\tUri {}\tRequestID {}\tNattacks\n"
CLEAN_FILE_LINE = "{}\n"
INDEX_NATTACKS_LINE = "\t{}"

# Functions
def init_parser():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(ERROR_LOG_ARG, help=ERROR_LOG_HELP, default=ERROR_LOG_DEFAULT, \
        metavar=ERROR_LOG_VARIABLE_NAME, dest=ERROR_LOG_VARIABLE_NAME)
    parser.add_argument(ACCESS_LOG_ARG, help=ACCESS_LOG_HELP, default=ACCESS_LOG_DEFAULT, \
        metavar=ACCESS_LOG_VARIABLE_NAME, dest=ACCESS_LOG_VARIABLE_NAME)
    parser.add_argument(IDENTIFIER_LOG_ARG, help=IDENTIFIER_LOG_HELP, default=IDENTIFIER_LOG_DEFAULT, \
        dest=IDENTIFIER_LOG_VARIABLE_NAME, metavar=IDENTIFIER_LOG_VARIABLE_NAME, type=int)
    return parser.parse_args()

def check_files(access_log_path, error_log_path):
    if not path.isfile(access_log_path):
        log.error(FILE_NOT_EXISTS_ERROR % access_log_path)
    if not path.isfile(error_log_path):
        log.error(FILE_NOT_EXISTS_ERROR % error_log_path)

def get_access_log_compiled_pattern():
    return re.compile(
        r'(?P<timestamp>\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\]) '
        r'\"GET (?P<uri>.+) HTTP\/1\.1\" '
        r'(?P<http_status>\d{3}) .+ '
        r'\"python-requests.+ '
        r'"request_id\":\"(?P<id>[a-zA-Z0-9]+)\"'
    )

def get_error_log_compiled_pattern():
    return re.compile(
        r'the request (?P<id>[a-zA-Z0-9]+) .+'
        r'rule ID (?P<rule_id>\d+)'
    )

def get_index_log_compiled_pattern():
    return re.compile(
        r'RequestID (?P<id>[a-zA-Z0-9]+)'
        r'\t(?P<nattacks>Nattacks)'
    )

def add_string_from_index(str, index, str_add):
    return str[:index] + str_add + str[index:]


def access_log_analysis(access_log_arg, index_file_name, clean_file_name):
    log.info(ANALYSIS_FILE_LOG_START.format(access_log_arg))
    access_log_cp = get_access_log_compiled_pattern()
    detected_uris = log.progress(DETECTED)
    undetected_uris = log.progress(UNDETECTED)

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

def error_log_analysis(error_log_arg, index_file_name):
    log.info(ANALYSIS_FILE_LOG_START.format(error_log_arg))
    number_of_attacks = log.progress(ADDING_NUMBER_OF_ATTACKS.format(index_file_name))
    index_log_cp = get_index_log_compiled_pattern()
    error_log_cp = get_error_log_compiled_pattern()


    error_log = open(error_log_arg, encoding='ISO-8859-1', errors='ignore')
    error_line = error_log.readline()
    index_file_count = 1
    for index_line in fileinput.input(index_file_name, inplace=True, backup='.bak'):
        number_of_attacks.status("%s" % index_file_count)
        
        result_index = index_log_cp.search(index_line)
        request_id = result_index.group('id')
        nattacks_end_position = result_index.end()
        
        searching_id = True
        id_not_changed = True
        nattacks_line = index_line
        while error_line and id_not_changed:
            result_error = error_log_cp.search(error_line)
            if result_error is not None:
                request_id_error_log = result_error.group('id')
                rule_id = result_error.group('rule_id')
                if request_id == request_id_error_log:
                    nattacks_line = add_string_from_index(nattacks_line, nattacks_end_position, \
                        INDEX_NATTACKS_LINE.format(rule_id))
                    searching_id = False
                    error_line = error_log.readline()
                elif not searching_id:
                    id_not_changed = False
                else:
                    error_line = error_log.readline()
            else:
                error_line = error_log.readline()
        if len(nattacks_line) > len(index_line):
            print(nattacks_line, end='')
        index_file_count += 1
    fileinput.close()
    error_log.close()
    log.info(ANALYSIS_ERROR_END_START.format(index_file_name))
    log.info(ANALYSIS_FILE_LOG_END.format(args.error_log))

# Main
args = init_parser()
check_files(args.access_log, args.error_log)
file_identifier = args.id
index_file_name = ANALYSIS_INDEX_FILE % file_identifier
clean_file_name = ANALYSIS_CLEAN_NAME % file_identifier

log.info(INFO_MAIN)
access_log_analysis(args.access_log, index_file_name, clean_file_name)
error_log_analysis(args.error_log, index_file_name)
log.info(END_MAIN)