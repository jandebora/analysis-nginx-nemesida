import argparse
from pwn import log

# Constant variables
DESCRIPTION = "Script that launches some URIs to specific URL"
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
LOG_INFO_MAIN_INIT = "Generating URI file..."
URI_LOG_WARN = "WARNING: Unrecognized URI: {} in line {}"
LOG_INFO_END = "File %s created"
FILE_NOT_EXISTS_ERROR = "File %s does not exist"

# Init parser parameters
parser = argparse.ArgumentParser(description=DESCRIPTION)
requiredArguments = parser.add_argument_group(REQUIRED_ARGS)
requiredArguments.add_argument(INPUT_ARG, help=INPUT_HELP, metavar=INPUT_VARIABLE_NAME, \
    dest=INPUT_VARIABLE_NAME, required=True)
parser.add_argument(OUTPUT_ARG, help=OUTPUT_HELP, metavar=OUTPUT_VARIABLE_NAME, \
    dest=OUTPUT_VARIABLE_NAME)
args = parser.parse_args()

# Functions
def output_file_def(input, output):
    if args.output is None:
        return input.replace(RAW_FILE, "")
    else:
        return output.split(URI_FILE)[0] + URI_FILE

# Main
log.info(LOG_INFO_MAIN_INIT)
output_file_name = output_file_def(args.input, args.output)

file_out = open(output_file_name, 'a')
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