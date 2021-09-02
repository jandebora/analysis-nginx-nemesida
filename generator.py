"""Script that generates a .uri file from a -raw.uri file. This script has been
developed in order to work with the dataset provided by the university

Usage: generator.py [-h] -i input [-o output]

optional arguments:
  -h, --help  show this help message and exit
  -o output   Output file parsed with specifics uris every line break. By
              default: ''input_file_name'.uri'

required arguments:
  -i input    Input file to be parsed in RAW format (fileName-raw.uri)


Author: Carlos Cagigao Bravo
"""

import argparse
from pwn import log
import re

# =====================================
# Constant variables
# =====================================
DESCRIPTION = "Script that generates a .uri file from a -raw.uri file. This script has been developed in order to work with the dataset provided by the university"
REQUIRED_ARGS = "required arguments"

INPUT_ARG = "-i"
INPUT_HELP = "Input file to be parsed in RAW format (fileName-raw.uri)"
INPUT_VARIABLE_NAME = "input"

OUTPUT_ARG = "-o"
OUTPUT_DEFAULT = "'input_file_name'.uri"
OUTPUT_HELP = "Output file parsed with specifics uris every line break. By default: '%s'" % OUTPUT_DEFAULT
OUTPUT_VARIABLE_NAME = "output"

URI_FILE = ".uri"
RAW_FILE = "-raw"
SLASH = "/"
WARN_FILE = "generator.warn"
LOG_INFO_MAIN = "Generating URI file..."
URI_LOG_WARN = "WARNING: Unrecognized uris detected. Check {} file".format(WARN_FILE)
URI_WARN = "WARNING: In line {}\tUnrecognized URI: {}"
LOG_INFO_END = "File %s created"
FILE_NOT_EXISTS_ERROR = "File %s does not exist"

# =====================================
# Functions
# =====================================
def output_file_def(input, output):
    """Define the output file name of .uri file

    :param input: input file name provided
    :type input: string
    :param output: output file name provided
    :type output: string

    :return: file name
    :rtype: string

    Examples:
        (0days-raw.uri,None) -> 0days.uri
        (0days-raw.uri, output) -> output.uri
        (input.uri, output.uri) -> output.uri
    """
    if output is None:
        return input.replace(RAW_FILE, "")
    else:
        return output.split(URI_FILE)[0] + URI_FILE

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
    parser.add_argument(OUTPUT_ARG, help=OUTPUT_HELP, metavar=OUTPUT_VARIABLE_NAME, \
        dest=OUTPUT_VARIABLE_NAME)

def add_required_arguments(required_arguments_group):
    """Add required arguments to argument parser group created and added previosly to the parser parent

    :param required_arguments_group: group added to ArgumentParser
    :type required_arguments_group: ArgumentParser.add_argument_group()
    """
    required_arguments_group.add_argument(INPUT_ARG, help=INPUT_HELP, metavar=INPUT_VARIABLE_NAME, \
        dest=INPUT_VARIABLE_NAME, required=True)

def get_raw_uri_file_compiled_pattern():
    """Creates the compiled pattern for -raw.uri files

    :return: compiled pattern
    :rtype: compiled pattern in re library

    Example of valid patterns:
    15 /..//etc/passwd
    21 /html/en/xprtCmd.html
    """
    return re.compile(r'\d+ (?P<uri>.+)')

def uri_fixer(uri):
    """Fixes the uri parsed as an argument adding it a slash if it doesn't have one.

    :param uri: valid URI
    :type uri: string

    :return: fixed uri
    :rtype: string

    Examples:
    '%20OR%201=1;%20--%20""}}"' => '/%20OR%201=1;%20--%20""}}"'
    '/..//etc/passwd' => '/..//etc/passwd'
    """
    if uri[0] != SLASH:
        return SLASH + uri
    return uri

def main(args):
    """Main function.
    
    Parses the raw uri file and generates a new file without 
    length number at the beginning of the line

    If the line is empty a warning log will be shown

    :param args: command-line retrieved arguments
    :type args: ArgumentParser.parse_args()

    :raises FileNotFoundError: if file does not exist
    """
    log.info(LOG_INFO_MAIN)
    output_file_name = output_file_def(args.input, args.output)

    file_out = open(output_file_name, 'w')
    file_warn = open(WARN_FILE, 'w')
    exist_warnings = False
    try:
        with open(args.input, 'r', encoding='ISO-8859-1', errors='ignore') as file:
            count = 1
            raw_cp = get_raw_uri_file_compiled_pattern()
            for line in file:
                result = raw_cp.search(line)
                if result is not None:
                    uri_first_index = result.span('uri')[0]
                    uri = uri_fixer(line[uri_first_index:])
                elif len(line)>0:
                    uri = uri_fixer(line)
                else:
                    exist_warnings = True
                    file_warn.write(URI_WARN.format(count, line))
                file_out.write(uri)
                count += 1
            file.close()
        file_out.close()
        file_warn.close()
        if exist_warnings:
            log.warn(URI_LOG_WARN)

    except FileNotFoundError:
        log.error(FILE_NOT_EXISTS_ERROR % args.file_location)

    log.info(LOG_INFO_END % output_file_name)

# =====================================
# Main
# =====================================
if __name__ == "__main__":
    args = init_parser().parse_args()
    main(args)