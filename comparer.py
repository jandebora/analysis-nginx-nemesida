"""Script that creates .attacks file from .index, .clean and .uri files

Usage: comparer.py [-h] -f file_location -id id

optional arguments:
  -h, --help        show this help message and exit

required arguments:
  -f file_location  File that contains some URIs to launch. This file must be
                    formatted previously
  -id id            Numeric value added to idenfity generated files

Author: Carlos Cagigao Bravo
"""

import argparse
from pwn import log
import subprocess

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

LOG_INFO_MAIN = "Starting comparison between .index, .clean and .uri files..."
LOG_INFO_END = "Files compared successfully. Created file {}"
FILE_NOT_EXISTS_ERROR = "File %s does not exist"
ATTACKS_EXT = "attacks"
CLEAN_EXT = "clean"
INDEX_EXT = "index"
ANALYSIS_FILE_NAME = "analysis-{}.{}"
ATTACKS_FILE_HEADER = \
    "---------------------- Statistics of URIs analyzed------------------------\n" + \
    "[{}] input, [{}] clean, [{}] attacks\n" + \
    "--------------------------- Analysis results -----------------------------\n"

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
    add_required_arguments(required_arguments)
    return parser

def add_required_arguments(required_arguments_group):
    """Add required arguments to argument parser group created and added previosly to the parser parent

    :param required_arguments_group: group added to ArgumentParser
    :type required_arguments_group: ArgumentParser.add_argument_group()
    """
    required_arguments_group.add_argument(FILE_ARG, help=FILE_HELP, metavar=FILE_VARIABLE_NAME, \
        dest=FILE_VARIABLE_NAME, required=True)
    required_arguments_group.add_argument(IDENTIFIER_ARG, help=IDENTIFIER_HELP, \
        dest=IDENTIFIER_VARIABLE_NAME, metavar=IDENTIFIER_VARIABLE_NAME, type=int, required=True)

def main(args):
    """Main function.

    Looks for lines number in files .index, .clean and .uri using wc -l command on linux shell, then
    puts the comparison header in file .attacks and completes it with a copy of .index file

    :raises FileNotFoundError: if file does not exist
    """
    log.info(LOG_INFO_MAIN)
    index_file_name = ANALYSIS_FILE_NAME.format(args.id, INDEX_EXT)
    clean_file_name = ANALYSIS_FILE_NAME.format(args.id, CLEAN_EXT)
    attacks_file_name = ANALYSIS_FILE_NAME.format(args.id, ATTACKS_EXT)

    index_line_numbers = subprocess.check_output(['wc', '-l', index_file_name]).__str__()
    index_line_numbers = index_line_numbers.split(' ')[0].replace("b'", "")
    clean_line_numbers = subprocess.check_output(['wc', '-l', clean_file_name]).__str__()
    clean_line_numbers = clean_line_numbers.split(' ')[0].replace("b'", "")
    uri_line_numbers = subprocess.check_output(['wc', '-l', args.file_location]).__str__()
    uri_line_numbers = int(uri_line_numbers.split(' ')[0].replace("b'", "")) + 1

    header = ATTACKS_FILE_HEADER.format(uri_line_numbers, clean_line_numbers, index_line_numbers)
    file_attacks = open(attacks_file_name, 'w')
    file_attacks.write(header)
    try:
        with open(index_file_name, encoding='ISO-8859-1', errors='ignore') as file:
            for line in file:
                file_attacks.write(line)
        file.close()
        file_attacks.close()
    except FileNotFoundError:
        log.error(FILE_NOT_EXISTS_ERROR % args.file_location)

    log.info(LOG_INFO_END.format(attacks_file_name))

# =====================================
# Main
# =====================================
if __name__ == "__main__":
    args = init_parser().parse_args()
    main(args)