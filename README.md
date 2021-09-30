# Analysis NGINX Nemesida
Detection research on attacks on Web servers based on HTTP URIs with Nemesida IDS

# Pre requirements
All this study has been executed on a CentOS 7 machine with the following specifications (```lsb_release -a```):
* LSB_version: core-4.1-amd64:core-4.1-noarch
* Distributor ID: CentOS
* Description: CentOS Linux release 7.9.2009 (Core)
* Release: 7.9.2009
* Codename: Core

# Nemesida WAF setup

First of all follow the [installation guide](https://nemesida-waf.com/about/1701) of Nemesida WAF.

## Nemesida on IDS mode
In order to don't block the attacks and see which of the urls sent would be blocked by the WAF rules, we are going to place Nemesida as an IDS, preventing the blocks.

To do this you simply have to modify the file ```/etc/nginx/nwaf/conf/global/nwaf.conf``` with the following value:

```
nwaf_limit rate=5r/m block_time=0;
```
## access_log setup
In order to be able to relate the error log with the access log, we must ensure that the file ```/etc/nginx/nginx.conf``` has the following configuration:

```
http {
    ...

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for" ' 
                      '"request_id":"$request_id" "block_type":$nwaf_block_type';

    access_log  /var/log/nginx/access.log  main;

    ...
}
```

Se ha añadido la última linea del ```log_format``` para poder identificar las peticiones que analiza nuestro WAF.

## Nemesida on docker
To configure nemesida in a docker container you must follow the following guide: [https://nemesida-waf.com/manuals/2685](https://nemesida-waf.com/manuals/2685).

Once configured we can use the file ```docker-compose.yml``` to run it more comfortably.

# Python3 environment setup

In order to don't load our Python version of our operating system with unwanted libraries, we are going to make use of the environments that it gives us. For this we have to execute the following commands to use and install the libraries in our environment.

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install --upgrade pip
pip3 install -r requirements/requirements
```
Once this is done we are ready to run our scripts.

If at any time you want to leave the environment that we have activated, we simply have to execute the following command in our console:

```bash
deactivate
```

# Running the tool

## All in one: start.py

```
Script that launches all parts of Nemesida WAF Analysis, in order: generator,
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
```

Example:

```
python start.py -i 0days100-raw.uri -f 0days100.uri -id 123456 -e logs/error.log -a logs/access.log
```

## Generator of .uri file: generator.py

```
Script that generates a .uri file from a -raw.uri file. This script has been
developed in order to work with the dataset provided by the university

Usage: generator.py [-h] -i input [-o output]

optional arguments:
  -h, --help  show this help message and exit
  -o output   Output file parsed with specifics uris every line break. By
              default: ''input_file_name'.uri'

required arguments:
  -i input    Input file to be parsed in RAW format (fileName-raw.uri)
```

Example:

``` 
python generator.py -i 0days-raw.uri
```

## URI Launcher: launcher.py
```
Script that launches some URIs to specific URL

Usage: launcher.py [-h] [-u url] [-p port] -f file_location

optional arguments:
  -h, --help        show this help message and exit
  -u url            URL protected by Nemesida WAF specified in NGINX
                    configuration file. By default: 'http://localhost'
  -p port           Specific port to launch the URIs from the file. By
                    default: '80'

required arguments:
  -f file_location  File that contains some URIs to launch. This file must be
                    formatted previously
```

Example:
```
python launcher.py -f 0days.uri
```

## Logs analyzer: analyzer.py
```
Script that parses Nemesida log files and generates a .index and .clean files
recovering necessary information to the research.

Usage: analyzer.py [-h] [-e error_log] [-a access_log] [-id id]

optional arguments:
  -h, --help     show this help message and exit
  -e error_log   Nginx error log file which contains information about
                 Nemesida blocked urls. By default: /var/log/nginx/error.log
  -a access_log  Nginx access log file which contains information about access
                 to the server. By default: /var/log/nginx/access.log
  -id id         Numeric value added to idenfity generated files. By default
                 is the current timestamp: ${current_timestamp}
```

Example:
```
python analyzer.py -e logs/error.log -a logs/access.log -id 123456789
```

## Analysis files comparer: comparer.py
```
Script that creates .attacks file from .index, .clean and access.log files

Usage: comparer.py [-h] [-a access_log] -id id

optional arguments:
  -h, --help     show this help message and exit
  -a access_log  Nginx access log file which contains information about access
                 to the server. By default: /var/log/nginx/access.log

required arguments:
  -id id         Numeric value added to idenfity generated files
```

Example:
```
python comparer.py -id 123456789 -a logs/access.log
```

## Launcher of dataset Biblio and INVES: dataset_looper.sh
```
Script that loops into dataset location and launches and analyzes
every .uri file contained in the folder

usage: ./dataset_looper dataset_name dataset_location

required arguments:
"dataset_name":         Name of dataset, valid values: "biblio" and "inves"
"dataset_location":     Dataset location (Biblio.uri or INVES.uri folder)
```

Example:
```
./dataset_looper biblio ~/home/usuario/datasets/Biblio.uri/
```