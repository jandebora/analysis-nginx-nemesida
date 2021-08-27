"""Script that launches some URIs to specific URL.

Usage: launcher.py [-h] [-u url] [-p port] [-f file_location]

optional arguments:
  -h, --help        show this help message and exit
  -u url            URL protected by Nemesida WAF specified in NGINX
                    configuration file. By default: 'http://localhost'
  -p port           Specific port to launch the URIs from the file. By
                    default: '80'
  -f file_location  File that contains some URIs to launch. This file must be
                    formatted previously.

Author: Carlos Cagigao Bravo
"""

import argparse
from urllib import parse, request, error
from pwn import log
import re

# =====================================
# Constant variables
# =====================================
DESCRIPTION = "Script that launches some URIs to specific URL"
REQUIRED_ARGS = "required arguments"

URL_ARG = "-u"
URL_DEFAULT = "http://localhost"
URL_HELP = "URL protected by Nemesida WAF specified in NGINX configuration file. By default: '%s'" % URL_DEFAULT
URL_VARIABLE_NAME = "url"

PORT_ARG = "-p"
PORT_DEFAULT = 80
PORT_HELP = "Specific port to launch the URIs from the file. By default: '%s'" % PORT_DEFAULT
PORT_VARIABLE_NAME = "port"

FILE_ARG = "-f"
FILE_HELP = "File that contains some URIs to launch. This file must be formatted previously"
FILE_VARIABLE_NAME = "file_location"

LOG_INFO_MAIN = "Sending attacks to {} on port {}"
LOG_PROGRESS_FILE = "File line number"
LOG_PROGRESS_URL = "Launching URL"
LOG_INFO_MAIN_END = "File launched successfully"
FILE_NOT_EXISTS_ERROR = "File %s does not exist"

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
    parser.add_argument(URL_ARG, help=URL_HELP, default=URL_DEFAULT, metavar=URL_VARIABLE_NAME, \
        dest=URL_VARIABLE_NAME)
    parser.add_argument(PORT_ARG, help=PORT_HELP, default=PORT_DEFAULT, metavar=PORT_VARIABLE_NAME, \
        dest=PORT_VARIABLE_NAME, type=int)

def add_required_arguments(required_arguments_group):
    """Add required arguments to argument parser group created and added previosly to the parser parent

    :param required_arguments_group: group added to ArgumentParser
    :type required_arguments_group: ArgumentParser.add_argument_group()
    """
    required_arguments_group.add_argument(FILE_ARG, help=FILE_HELP, metavar=FILE_VARIABLE_NAME, \
        dest=FILE_VARIABLE_NAME, required=True)

def main(args):
    """Main function.
    
    Launches the uris contained in file to specific url retrieved on launch parameters.

    All uris are encoded before launch and all line break contained at the end of each line 
    of the file will be deleted

    :param args: command-line retrieved arguments
    :type args: ArgumentParser.parse_args()

    :raises FileNotFoundError: if file does not exist
    """
    log.info(LOG_INFO_MAIN.format(args.url, args.port))
    progress_file = log.progress(LOG_PROGRESS_FILE)
    progress_url_launch = log.progress(LOG_PROGRESS_URL)

    url = args.url
    if args.port != PORT_DEFAULT:
        url = args.url + ":" + str(args.port)

    try:
        with open(args.file_location, 'r') as file:
            count = 1
            for line in file:
                try:
                    line_without_line_break = re.sub(r'\n$', '', line)
                    progress_file.status("%s" % count)
                    progress_url_launch.status("%s" % line_without_line_break)
                    encoded_uri = parse.quote(line_without_line_break, safe="/:=?&")
                    request.urlopen(url + encoded_uri, timeout=1)
                    count += 1
                except error.HTTPError:
                    count += 1
                    pass
        file.close()
        log.info(LOG_INFO_MAIN_END)
    except FileNotFoundError:
        log.error(FILE_NOT_EXISTS_ERROR % args.file_location)

# =====================================
# Main
# =====================================
if __name__ == "__main__":
    args = init_parser().parse_args()
    main(args)