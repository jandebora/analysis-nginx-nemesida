"""Script that creates .attacks file from .index, .clean and .uri files

Usage: comparer.py [-h] [-a access_log] -f file_location -id id

optional arguments:
  -h, --help        show this help message and exit
  -a access_log     Nginx access log file which contains information about
                    access to the server. By default:
                    /var/log/nginx/access.log

required arguments:
  -f file_location  File that contains some URIs to launch. This file must be
                    formatted previously
  -id id            Numeric value added to idenfity generated files

Author: Carlos Cagigao Bravo
"""

import argparse
from pwn import log
import subprocess
import re

# =====================================
# Constant variables
# =====================================
DESCRIPTION = "Script that creates .attacks file from .index, .clean and .uri files"
REQUIRED_ARGS = "required arguments"

IDENTIFIER_ARG = "-id"
IDENTIFIER_HELP = "Numeric value added to idenfity generated files"
IDENTIFIER_VARIABLE_NAME = "id"

FILE_ARG = "-f"
FILE_HELP = "File that contains some URIs to launch. This file must be formatted previously"
FILE_VARIABLE_NAME = "file_location"

ACCESS_LOG_ARG = "-a"
ACCESS_LOG_DEFAULT = "/var/log/nginx/access.log"
ACCESS_LOG_HELP = "Nginx access log file which contains information about access to the server. By default: %s" \
     % ACCESS_LOG_DEFAULT
ACCESS_LOG_VARIABLE_NAME = "access_log"

LOG_INFO_MAIN = "Starting comparison between .index, .clean and .uri files..."
LOG_INFO_END = "Files compared successfully. Created file {}"
CHECK_INDEX_URI_IN_RAW = "Matching .index URIs with access log file"
FILE_NOT_EXISTS_ERROR = "File %s does not exist"
ATTACKS_EXT = "attacks"
CLEAN_EXT = "clean"
INDEX_EXT = "index"
ANALYSIS_FILE_NAME = "analysis-{}.{}"
ATTACKS_FILE_HEADER = \
    "---------------------- Statistics of URIs analyzed------------------------\n" + \
    "[{}] input, [{}] clean, [{}] attacks\n" + \
    "--------------------------- Analysis results -----------------------------\n"
ISO_8859_1 = "ISO-8859-1"
PACKET_DATA = "Packet [{}]\t"

# =====================================
# Functions
# =====================================
def init_parser():
    """Retrieves the parameters with which it has been executed

    :rtype: ArgumentParser
    :return: arguments prepared to be parsed
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    required_arguments = parser.add_argument_group(REQUIRED_ARGS)
    add_optional_arguments(parser)
    add_required_arguments(required_arguments)
    return parser

def add_optional_arguments(parser):
    """Add optional arguments to parser

    :param parser: parser to add arguments
    :type parser: ArgumentParser
    """
    parser.add_argument(ACCESS_LOG_ARG, help=ACCESS_LOG_HELP, default=ACCESS_LOG_DEFAULT, \
        metavar=ACCESS_LOG_VARIABLE_NAME, dest=ACCESS_LOG_VARIABLE_NAME)

def add_required_arguments(required_arguments_group):
    """Add required arguments to argument parser group created and 
    added previosly to the parser parent

    :param required_arguments_group: group added to ArgumentParser
    :type required_arguments_group: ArgumentParser.add_argument_group()
    """
    required_arguments_group.add_argument(FILE_ARG, help=FILE_HELP, metavar=FILE_VARIABLE_NAME, \
        dest=FILE_VARIABLE_NAME, required=True)
    required_arguments_group.add_argument(IDENTIFIER_ARG, help=IDENTIFIER_HELP, \
        dest=IDENTIFIER_VARIABLE_NAME, metavar=IDENTIFIER_VARIABLE_NAME, type=int, required=True)

def get_index_file_cp():
    """Creates the compiled pattern for .index file
    
    :return: compiled pattern
    :rtype: compiled pattern in re library

    Example of valid pattern:
        '[17/Aug/2021:19:27:10 +0200]\t'
        'Uri [/wp-admin/admin-ajax.php]\t'
        'RequestID [e90f9480d500cad488650afb3a73c854]\t'
    """
    return re.compile(
        r'(?P<timestamp>\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\]\t)'
        r'Uri \[(?P<uri>.+)\]\t'
        r'RequestID \[(?P<id>[a-zA-Z0-9]+)\]\t'
    )

def get_access_log_compiled_pattern():
    """Creates the compiled pattern for Nginx access.log
    
    :return: compiled pattern
    :rtype: compiled pattern in re library

    Example of valid pattern:
        '"request_id":"e90f9480d500cad488650afb3a73c854" '
    """
    return re.compile(r'"request_id\":\"(?P<id>[a-zA-Z0-9]+)\" ')

def get_attacks_header(index_file_name, clean_file_name, uri_file_location):
    """Defines the header for .attack file

    :param index_file_name: name of .index file
    :type index_file_name: string
    :param clean_file_name: name of .clean file
    :type clean_file_name: string
    :param uri_file_location: location of .uri file
    :type uri_file_location: string

    :return: header, constant ATTACKS_FILE_HEADER formatted
    :rtype: string
    """
    index_line_numbers = subprocess.check_output(['wc', '-l', index_file_name]).__str__()
    index_line_numbers = index_line_numbers.split(' ')[0].replace("b'", "")
    clean_line_numbers = subprocess.check_output(['wc', '-l', clean_file_name]).__str__()
    clean_line_numbers = clean_line_numbers.split(' ')[0].replace("b'", "")
    uri_line_numbers = subprocess.check_output(['wc', '-l', uri_file_location]).__str__()
    uri_line_numbers = int(uri_line_numbers.split(' ')[0].replace("b'", ""))

    return ATTACKS_FILE_HEADER.format(uri_line_numbers, clean_line_numbers, index_line_numbers)

def compare_access_log_and_index(access_log_arg, index_file_name, attacks_file):
    """Compares access.log and .index files adding Packet[NUM] information at the beginning
    of the line. NUM represents the line which contains the URI in original .uri file

    :param access_log_arg: access.log location as an argument
    :type access_log_arg: string
    :param index_file_name: name of .index file
    :type index_file_name: string
    :param attacks_file: previosly created .attack file
    :type attacks_file: file
    """
    access_log_arg = access_log_arg
    index_file_cp = get_index_file_cp()
    access_log_cp = get_access_log_compiled_pattern()
    try:
        with open(index_file_name, encoding=ISO_8859_1, errors='ignore') as index_file:
            access_log = open(access_log_arg, encoding=ISO_8859_1, errors='ignore')
            access_log_line = access_log.readline()
            access_log_count = 1
            progress_index_file = log.progress(CHECK_INDEX_URI_IN_RAW)
            for index_count, index_line in enumerate(index_file):
                progress_index_file.status("%s" % str(index_count + 1))
                result = index_file_cp.search(index_line)
                if result is not None:
                    last_timestamp_index = result.span('timestamp')[1]
                    request_id = result.group('id')
                    searching_uri = True
                    while(access_log_line and searching_uri):
                        result_access_log = access_log_cp.search(access_log_line)
                        if result_access_log is not None:
                            request_id_access_log = result_access_log.group('id')
                            if request_id == request_id_access_log:
                                searching_uri = False
                                attack_line = PACKET_DATA.format(access_log_count) + index_line[last_timestamp_index:]
                                attacks_file.write(attack_line)
                        access_log_count += 1
                        access_log_line = access_log.readline()
        access_log.close()
        attacks_file.close()
    except FileNotFoundError:
        log.error(FILE_NOT_EXISTS_ERROR % args.file_location)

def main(args):
    """Main function.

    Looks for lines number in files .index, .clean, .uri using wc -l command on linux shell, then
    puts the comparison header in file .attacks and completes it with a copy of .index file adding
    PACKET[NUM] information at the beginning of the line

    :raises FileNotFoundError: if file does not exist
    """
    log.info(LOG_INFO_MAIN)
    index_file_name = ANALYSIS_FILE_NAME.format(args.id, INDEX_EXT)
    clean_file_name = ANALYSIS_FILE_NAME.format(args.id, CLEAN_EXT)
    attacks_file_name = ANALYSIS_FILE_NAME.format(args.id, ATTACKS_EXT)

    header = get_attacks_header(index_file_name, clean_file_name, args.file_location)
    attacks_file = open(attacks_file_name, 'w')
    attacks_file.write(header)
    compare_access_log_and_index(args.access_log, index_file_name, attacks_file)

    log.info(LOG_INFO_END.format(attacks_file_name))

# =====================================
# Main
# =====================================
if __name__ == "__main__":
    args = init_parser().parse_args()
    main(args)