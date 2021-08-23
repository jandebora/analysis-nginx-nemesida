"""Script that launches all parts of Nemesida WAF Analysis, in order: generator,
launcher, analyzer, comparer

Usage: start.py [-h] [-o output] [-u url] [-p port] [-e error_log]
                [-a access_log] -i input -f file_location -id id

optional arguments:
  -h, --help        show this help message and exit
  -o output         Output file parsed with specifics uris every line break.
                    By default: ''input_file_name'.uri'
  -u url            URL protected by Nemesida WAF specified in NGINX
                    configuration file. By default: 'http://localhost'
  -p port           Specific port to launch the URIs from the file. By
                    default: '80'
  -e error_log      Nginx error log file which contains information about
                    Nemesida blocked urls. By default:
                    /var/log/nginx/error.log
  -a access_log     Nginx access log file which contains information about
                    access to the server. By default:
                    /var/log/nginx/access.log

required arguments:
  -i input          Input file to be parsed in RAW format (fileName-raw.uri)
  -f file_location  File that contains some URIs to launch. This file must be
                    formatted previously
  -id id            Numeric value added to idenfity generated files

Author: Carlos Cagigao Bravo
"""

import argparse
import launcher
import generator
import analyzer
import comparer

# =====================================
# Constant variables
# =====================================
DESCRIPTION = "Script that launches all parts of Nemesida WAF Analysis, in order: \
    generator, launcher, analyzer, comparer"
REQUIRED_ARGS = "required arguments"


# =====================================
# Functions
# =====================================
def init_parser():
    """Retrieves the parameters with which are going to be executed in
    differents scripts (launcher, generator, analyzer and comparer)

    :rtype: ArgumentParser
    :return: arguments prepared to be parsed
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    required_arguments = parser.add_argument_group(REQUIRED_ARGS)

    generator.add_optional_arguments(parser)
    launcher.add_optional_arguments(parser)
    analyzer.add_optional_arguments(parser, True)

    generator.add_required_arguments(required_arguments)
    launcher.add_required_arguments(required_arguments)
    analyzer.add_required_arguments(required_arguments)

    return parser

def main(args):
    """Main function.

    First check for log files existence and then uses main from 
    previous script in order to launch sequentially

    :raises PwnlibException: if file does not exists
    """
    analyzer.check_files(args.access_log, args.error_log)
    generator.main(args)
    print()
    launcher.main(args)
    print()
    analyzer.main(args)
    print()
    comparer.main(args)

# =====================================
# Main
# =====================================
if __name__ == "__main__":
    args = init_parser().parse_args()
    main(args)