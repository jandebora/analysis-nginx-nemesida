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
LOG_INFO_MAIN = "Generating URI file..."
URI_LOG_WARN = "WARNING: Unrecognized URI: {} in line {}"
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

    :rtype: list of arguments
    :return: retrieved arguments
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    requiredArguments = parser.add_argument_group(REQUIRED_ARGS)
    requiredArguments.add_argument(INPUT_ARG, help=INPUT_HELP, metavar=INPUT_VARIABLE_NAME, \
        dest=INPUT_VARIABLE_NAME, required=True)
    parser.add_argument(OUTPUT_ARG, help=OUTPUT_HELP, metavar=OUTPUT_VARIABLE_NAME, \
        dest=OUTPUT_VARIABLE_NAME)
    return parser.parse_args()

def main():
    """Main function.
    
    Parses the raw uri file and generates a new file without 
    length number at the beginning of the line

    If the line does not contains '/' or is an invalid URI, a warning log will be shown

    :raises FileNotFoundError: if file does not exists
    """
    args = init_parser()
    log.info(LOG_INFO_MAIN)
    output_file_name = output_file_def(args.input, args.output)

    file_out = open(output_file_name, 'w')
    try:
        with open(args.input, 'r', encoding='ISO-8859-1', errors='ignore') as file:
            count = 1
            for line in file:
                first_spacebar = line.find('/')
                if (first_spacebar > 0):
                    line_parsed = line[first_spacebar:]
                    file_out.write(line_parsed)
                else:
                    log.warn(URI_LOG_WARN.format(line, count))
                count += 1
            file.close()
        file_out.close()
    except FileNotFoundError:
        log.error(FILE_NOT_EXISTS_ERROR % args.file_location)

    log.info(LOG_INFO_END % output_file_name)

# =====================================
# Main
# =====================================
if __name__ == "__main__":
    main()