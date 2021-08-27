"""Script that parses Nemesida log files and generates a .index and .clean files
recovering necessary information to the research.

Usage: analyzer.py [-h] [-e error_log] [-a access_log] [-id id]

optional arguments:
  -h, --help     show this help message and exit
  -e error_log   Nginx error log file which contains information about
                 Nemesida blocked urls. By default: /var/log/nginx/error.log
  -a access_log  Nginx access log file which contains information about access
                 to the server. By default: /var/log/nginx/access.log
  -id id         Numeric value added to idenfity generated files. By default
                 is the current timestamp: ${current_timestamp}

Author: Carlos Cagigao Bravo
"""

import argparse
from pwn import log
from datetime import datetime
import re
from urllib import parse
import os.path as path
import fileinput

# =====================================
# Constant variables
# =====================================
DESCRIPTION = "Script that parses Nemesida log files and generates a .index and .clean files recovering necessary \
    information to the research."

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
IDENTIFIER_LOG_HELP = "Numeric value added to idenfity generated files"
IDENTIFIER_LOG_HELP_DEFAULT = ". By default is the current timestamp: %s" % IDENTIFIER_LOG_DEFAULT
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
END_MAIN = "Analysis completed successfully"

INDEX_FILE_LINE = "{}\tUri {}\tRequestID {}\tNattacks\n"
CLEAN_FILE_LINE = "{}\n"
INDEX_NATTACKS_LINE = "\t{}"

# =====================================
# Functions
# =====================================
def init_parser():
    """Retrieves the parameters with which it has been executed

    :rtype: ArgumentParser
    :return: arguments prepared to be parsed
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    add_optional_arguments(parser, False)
    return parser

def add_optional_arguments(parser, id_required):
    """Add optional arguments to parser

    If id is not required add it to optional

    :param parser: parser to add arguments
    :type parser: ArgumentParser
    :param id_required: if id is required or not
    :type id_required: boolean
    """
    parser.add_argument(ERROR_LOG_ARG, help=ERROR_LOG_HELP, default=ERROR_LOG_DEFAULT, \
        metavar=ERROR_LOG_VARIABLE_NAME, dest=ERROR_LOG_VARIABLE_NAME)
    parser.add_argument(ACCESS_LOG_ARG, help=ACCESS_LOG_HELP, default=ACCESS_LOG_DEFAULT, \
        metavar=ACCESS_LOG_VARIABLE_NAME, dest=ACCESS_LOG_VARIABLE_NAME)

    if not id_required:
        help_string = IDENTIFIER_LOG_HELP + IDENTIFIER_LOG_HELP_DEFAULT
        parser.add_argument(IDENTIFIER_LOG_ARG, help=help_string, default=IDENTIFIER_LOG_DEFAULT, \
        dest=IDENTIFIER_LOG_VARIABLE_NAME, metavar=IDENTIFIER_LOG_VARIABLE_NAME, type=int)

def add_required_arguments(required_arguments_group):
    """Add required arguments to argument parser group created and added previosly to the parser parent

    :param required_arguments_group: group added to ArgumentParser
    :type required_arguments_group: ArgumentParser.add_argument_group()
    """
    required_arguments_group.add_argument(IDENTIFIER_LOG_ARG, help=IDENTIFIER_LOG_HELP, \
        dest=IDENTIFIER_LOG_VARIABLE_NAME, metavar=IDENTIFIER_LOG_VARIABLE_NAME, type=int, required=True)

def check_files(access_log_path, error_log_path):
    """Check for indicated files existence

    :raises PwnlibException: if file does not exist
    """
    if not path.isfile(access_log_path):
        log.error(FILE_NOT_EXISTS_ERROR % access_log_path)
    if not path.isfile(error_log_path):
        log.error(FILE_NOT_EXISTS_ERROR % error_log_path)

def get_access_log_compiled_pattern():
    """Creates the compiled pattern for access log file
    
    :return: compiled pattern
    :rtype: compiled pattern in re library

    Example of valid pattern:
        '[17/Aug/2021:19:27:10 +0200] '
        '"GET /wp-admin/admin-ajax.php HTTP/1.1" '
        '"request_id":"e90f9480d500cad488650afb3a73c854"'
    """
    return re.compile(
        r'(?P<timestamp>\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\]) '
        r'\"GET (?P<uri>.+) HTTP\/1\.1\" '
        r'(?P<http_status>\d{3}) .+ '
        r'"request_id\":\"(?P<id>[a-zA-Z0-9]+)\"'
    )

def get_error_log_compiled_pattern():
    """Creates the compiled pattern for error log file
    
    :return: compiled pattern
    :rtype: compiled pattern in re library

    Example of valid pattern:
        'the request e90f9480d500cad488650afb3a73c854 blocked '
        'rule ID 1567'
    """
    return re.compile(
        r'the request (?P<id>[a-zA-Z0-9]+) .+'
        r'rule ID (?P<rule_id>\d+)'
    )

def get_index_log_compiled_pattern():
    """Creates the compiled pattern for .index file
    
    :return: compiled pattern
    :rtype: compiled pattern in re library
    
    Example of valid pattern:
        'RequestID e90f9480d500cad488650afb3a73c854     '
        'Nattacks'
    """
    return re.compile(
        r'RequestID (?P<id>[a-zA-Z0-9]+)'
        r'\t(?P<nattacks>Nattacks)'
    )

def add_string_from_index(str, index, str_add):
    """Add a string in specific index

    :param str: string that is going to be changed
    :type str: string
    :param index: index from which string are going to be modified
    :type index: int
    :param str_add: string to add
    :type str_add: string
    
    """
    return str[:index] + str_add + str[index:]

def create_list_of_file_pos(file):
    """Creates a list of file positions in order to use file.seek(position)
    to access concrete lines into the file with distinct length between lines

    :param file: previosly opened file
    :type file: file in read mode

    :return: list of positions
    :rtype: list
    """
    list_pos = list()
    pos = 0
    length = 0
    for each in file:
        list_pos.append(length)
        length = length + len(each)
        pos += 1
    
    return list_pos

def give_file_line_by_pos(file, pos):
    """Return specific file line by position with file.seek(position)

    :param file: previosly opened file
    :type file: file in read mode
    :param pos: position in the file (to use with file.seek())
    :type pos: int

    :return: file line
    :rtype: string
    """
    file.seek(pos)

    return file.readline()


def access_log_analysis(access_log_arg, index_file_name, clean_file_name):
    """Analyzes the access log file and creates a completed .clean file and uncompleted .index file.
    Index file needs to be completed analyzing error log file in the next step
    
    :param access_log_arg: access log retrieved from command line
    :type access_log_arg: string
    :param index_file_name: name of the index file name to be created
    :type index_file_name: string
    :param clean_file_name: name of the clean file name to be created
    :type clean_file_name: string
    """
    log.info(ANALYSIS_FILE_LOG_START.format(access_log_arg))
    access_log_cp = get_access_log_compiled_pattern()
    detected_uris = log.progress(DETECTED)
    undetected_uris = log.progress(UNDETECTED)

    clean_file = open(clean_file_name, 'w')
    index_file = open(index_file_name, 'w')
    with open(access_log_arg, encoding='ISO-8859-1', errors='ignore') as log_file:
        detected_count = 0
        undetected_count = 0
        for line in log_file:
            result = access_log_cp.search(line)
            if result is not None:
                uri = result.group('uri')
                decoded_uri = parse.unquote(uri)
                if result.group('http_status') == '403':
                    timestamp = result.group('timestamp')
                    request_id = result.group('id')
                    index_file.write(INDEX_FILE_LINE.format(timestamp, decoded_uri, request_id))
                    detected_count += 1
                    detected_uris.status("%s" % detected_count)
                else:
                    clean_file.write(CLEAN_FILE_LINE.format(decoded_uri))
                    undetected_count += 1
                    undetected_uris.status("%s" % undetected_count)
    log_file.close()
    clean_file.close()
    index_file.close()

    log.info(ANALYSIS_FILE_LOG_END.format(access_log_arg))
    log.info(FILES_GENERATED.format(index_file_name, clean_file_name))

def error_log_analysis(error_log_arg, index_file_name):
    """Analyzes the error log file and completes the .index file adding number of attacks
    at the end of the file separated by tabs.
    
    :param error_log_arg: error log retrieved from command line
    :type error_log_arg: string
    :param index_file_name: name of the index file name to be created
    :type index_file_name: string
    """
    log.info(ANALYSIS_FILE_LOG_START.format(error_log_arg))
    number_of_attacks = log.progress(ADDING_NUMBER_OF_ATTACKS.format(index_file_name))
    index_log_cp = get_index_log_compiled_pattern()
    error_log_cp = get_error_log_compiled_pattern()

    error_log = open(error_log_arg, encoding='ISO-8859-1', errors='ignore')
    list_pos = create_list_of_file_pos(error_log)
    list_length = len(list_pos)
    index_file_count = 1
    for index_line in fileinput.input(index_file_name, inplace=True):
        number_of_attacks.status("%s" % index_file_count)
        
        result_index = index_log_cp.search(index_line)
        request_id = result_index.group('id')

        count_file_idx = 0
        searching_id = True
        id_not_changed = True
        nattacks_line = index_line
        while count_file_idx < list_length and id_not_changed:
            error_line = give_file_line_by_pos(error_log, list_pos[count_file_idx])
            result_error = error_log_cp.search(error_line)
            if result_error is not None:
                request_id_error = result_error.group('id')
                rule_id = result_error.group('rule_id')
                if request_id  == request_id_error:
                    nattacks_line = add_string_from_index(nattacks_line, result_index.end(), \
                        INDEX_NATTACKS_LINE.format(rule_id))
                    list_pos.pop(count_file_idx)
                    list_length -= 1
                    searching_id = False
                elif not searching_id:
                    id_not_changed = False
                else:
                    count_file_idx += 1
            else:
                list_pos.pop(count_file_idx)
                list_length -= 1
        if len(nattacks_line) > len(index_line):
            print(nattacks_line, end='')
        index_file_count += 1
    fileinput.close()
    error_log.close()
    log.info(ANALYSIS_FILE_LOG_END.format(error_log_arg))

def main(args):
    """Main function.
    
    Executes analysis for access log and error log adding some log info 
    before and after the process.

    :param args: command-line retrieved arguments
    :type args: ArgumentParser.parse_args()
    """
    check_files(args.access_log, args.error_log)
    file_identifier = args.id
    index_file_name = ANALYSIS_INDEX_FILE % file_identifier
    clean_file_name = ANALYSIS_CLEAN_NAME % file_identifier

    log.info(INFO_MAIN)
    access_log_analysis(args.access_log, index_file_name, clean_file_name)
    error_log_analysis(args.error_log, index_file_name)
    log.info(END_MAIN)

# =====================================
# Main
# =====================================
if __name__ == "__main__":
    args = init_parser().parse_args()
    main(args)