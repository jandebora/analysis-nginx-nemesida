import requests, time, sys, signal
import argparse
import urllib.request

# Constant variables
DESCRIPTION = "Script that launches some URIs to specific URL"

URL_ARGUMENT = "-u"
URL_DEFAULT = "http://localhost/"
URL_HELP = "URL protected by Nemesida WAF specified in NGINX configuration file. By default: '%s'" % URL_DEFAULT
URL_VARIABLE_NAME = "url"

PORT_ARGUMENT = "-p"
PORT_DEFAULT = 80
PORT_HELP = "Specific port to launch the URIs from the file. By default: '%s'" % PORT_DEFAULT
PORT_VARIABLE_NAME = "port"

FILE_ARGUMENT = "-f"
FILE_DEFAULT = "default_file.uri"
FILE_HELP = "File that contains some URIs to launch. This file must be formatted previously. \
    By default: '%s'" % FILE_DEFAULT
FILE_VARIABLE_NAME = "file_location"

# Init parser parameters
parser = argparse.ArgumentParser(description=DESCRIPTION)
parser.add_argument(URL_ARGUMENT, help=URL_HELP, default=URL_DEFAULT, metavar=URL_VARIABLE_NAME, \
    dest=URL_VARIABLE_NAME)
parser.add_argument(PORT_ARGUMENT, help=PORT_HELP, default=PORT_DEFAULT, metavar=PORT_VARIABLE_NAME, \
     dest=PORT_VARIABLE_NAME, type=int)
parser.add_argument(FILE_ARGUMENT, help=FILE_HELP, default=FILE_DEFAULT, metavar=FILE_VARIABLE_NAME, \
    dest=FILE_VARIABLE_NAME)
args = parser.parse_args()

# Sending help if no arguments provided
if (len(sys.argv) < 2):
    parser.print_help(sys.stderr)

print(args)