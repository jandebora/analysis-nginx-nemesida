import argparse
from pwn import log
import time
from datetime import datetime

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

LOG_INFO_MAIN_INIT = "Analyzing logs..."
FILE_NOT_EXISTS_ERROR = "File %s does not exist"
OUTPUT_FILE_NAME = "analysis-%s.index"

# Functions

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

log.info(LOG_INFO_MAIN_INIT)
try:
    file_out = open(output_file_name, 'a')
    with open(args.error_log, encoding='ISO-8859-1', errors='ignore') as log_file:
        count = 0
        for line in log_file:
            count +=1
        print(count)
    log_file.close()
    file_out.close()
except FileNotFoundError:
    log.error(FILE_NOT_EXISTS_ERROR)