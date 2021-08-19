import requests
import argparse
from urllib import parse
from pwn import log
import re

# Constant variables
DESCRIPTION = "Script that launches some URIs to specific URL"

URL_ARG = "-u"
URL_DEFAULT = "http://localhost"
URL_HELP = "URL protected by Nemesida WAF specified in NGINX configuration file. By default: '%s'" % URL_DEFAULT
URL_VARIABLE_NAME = "url"

PORT_ARG = "-p"
PORT_DEFAULT = 80
PORT_HELP = "Specific port to launch the URIs from the file. By default: '%s'" % PORT_DEFAULT
PORT_VARIABLE_NAME = "port"

FILE_ARG = "-f"
FILE_DEFAULT = "default_file.uri"
FILE_HELP = "File that contains some URIs to launch. This file must be formatted previously. \
    By default: '%s'" % FILE_DEFAULT
FILE_VARIABLE_NAME = "file_location"

LOG_INFO_MAIN = "Sending attacks to {} on port {}"
LOG_PROGRESS_FILE = "File line number"
LOG_PROGRESS_URL = "Launching URL"
LOG_INFO_MAIN_END = "File successfully launched"
FILE_NOT_EXISTS_ERROR = "File %s does not exist"

# Init parser parameters
parser = argparse.ArgumentParser(description=DESCRIPTION)
parser.add_argument(URL_ARG, help=URL_HELP, default=URL_DEFAULT, metavar=URL_VARIABLE_NAME, \
    dest=URL_VARIABLE_NAME)
parser.add_argument(PORT_ARG, help=PORT_HELP, default=PORT_DEFAULT, metavar=PORT_VARIABLE_NAME, \
     dest=PORT_VARIABLE_NAME, type=int)
parser.add_argument(FILE_ARG, help=FILE_HELP, default=FILE_DEFAULT, metavar=FILE_VARIABLE_NAME, \
    dest=FILE_VARIABLE_NAME)
args = parser.parse_args()

# Main 
log.info(LOG_INFO_MAIN.format(args.url, args.port))
progress_file = log.progress(LOG_PROGRESS_FILE)
progress_url_launch = log.progress(LOG_PROGRESS_URL)

url = args.url
if args.port != PORT_DEFAULT:
    url = args.url + ":" + str(args.port)

try:
    with open(args.file_location, 'r') as file:
        count = 0
        for line in file:
            line_without_line_break = re.sub(r'\n$', '', line)
            progress_file.status("%s" % count)
            progress_url_launch.status("%s" % line_without_line_break)
            encoded_uri = parse.quote(line_without_line_break)
            requests.get(url + encoded_uri, verify=False, timeout=1)
            count += 1
    file.close()
    log.info(LOG_INFO_MAIN_END)
except FileNotFoundError:
    log.error(FILE_NOT_EXISTS_ERROR % args.file_location)