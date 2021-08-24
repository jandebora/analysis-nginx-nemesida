# Analysis NGINX Nemesida
Estudio de detección de ataques a servidores Web basados en URIs HTTP con IDS Nemesida

# Pre-requisitos
Todo este estudio ha sido ejecutado en una máquina CentOS 7 con las siguientes especificaciones (```lsb_release -a```):
* LSB_version: core-4.1-amd64:core-4.1-noarch
* Distributor ID: CentOS
* Description: CentOS Linux release 7.9.2009 (Core)
* Release: 7.9.2009
* Codename: Core

# Instalación Nemesida WAF

En primer lugar seguimos la [guía de instalación](https://nemesida-waf.com/about/1701) del Web Application Firewall Nemesida.

**Por comodidad, nuestra máquina CentOS no tiene el PATH apropiado. Hay que añadir /usr/sbin a través del archivo ```.bash_profile```**

## Nemesida como IDS
Con objeto de no bloquear los ataques y simplemente ver cuales de las urls enviadas serían bloqueadas por las reglas del WAF, vamos a colocar a Nemesida como un IDS, impidiendo los bloqueos.

Para ello simplemente hay que modificar en el archivo ```/etc/nginx/nwaf/conf/global/nwaf.conf``` con el siguiente valor:

```
nwaf_limit rate=5r/m block_time=0;
```
## Configuración del access_log
Con motivo de poder relacionar el log de error con el de accesos, debemos asegurar que el fichero ```/etc/nginx/nginx.conf``` tenga la siguiente configuración:

```
http {
    ...

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for" ' 
                      '"request_id":"$request_id"';

    access_log  /var/log/nginx/access.log  main;

    ...
}
```

Se ha añadido la última linea del ```log_format``` para poder identificar las peticiones que analiza nuestro WAF.

## Nemesida en docker
Para configurar nemesida en un contenedor de docker hay que seguir la siguiente guía: [https://nemesida-waf.com/manuals/2685](https://nemesida-waf.com/manuals/2685).

Una vez configurado podemos hacer uso del archivo ```docker-compose.yml``` para ejecutarlo de forma más cómoda.

# Configuración environment Python3

Con objeto de no cargar nuestra versión de Python de nuestro sistema operativo con librerías indeseadas, vamos a hacer uso de los environments que nos aporta. Para ello tenemos que ejecutar los siguientes comandos para usar e instalar las librerías en nuestro entorno.

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install --upgrade pip
pip3 install -r requirements/requirements
```
Una vez hecho esto estaremos preparados para ejecutar nuestros scripts.

Si en algún momento se desea salir del entorno que tenemos activado simplemente tenemos que ejecutar el siguiente comando en nuestra consola:

```bash
deactivate
```

# Funcionamiento

## Todo en uno: start.py

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

Ejemplo de uso típico:

```
python start.py -i 0days100-raw.uri -f 0days100.uri -id 123456 -e logs/error.log -a logs/access.log
```

## Generador de fichero .uri: generator.py

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

Ejemplo de uso:

``` 
python generator.py -i 0days-raw.uri
```

## Lanzador de URIs: launcher.py
```
Script that launches some URIs to specific URL.

Usage: launcher.py [-h] [-u url] [-p port] [-f file_location]

optional arguments:
  -h, --help        show this help message and exit
  -u url            URL protected by Nemesida WAF specified in NGINX
                    configuration file. By default: 'http://localhost'
  -p port           Specific port to launch the URIs from the file. By
                    default: '80'
  -f file_location  File that contains some URIs to launch. This file must be
                    formatted previously. By default: 'default_file.uri'
```

Ejemplo de uso:
```
python launcher.py -f 0days.uri
```

## Analizador de logs: analyzer.py
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

Ejemplo de uso:
```
python analyzer.py -e logs/error.log -a logs/access.log -id 123456789
```

## Comparador de ficheros del análisis: comparer.py
```
Script that creates .attacks file from .index, .clean and .uri files

Usage: comparer.py [-h] -f file_location -id id

optional arguments:
  -h, --help        show this help message and exit

required arguments:
  -f file_location  File that contains some URIs to launch. This file must be
                    formatted previously
  -id id            Numeric value added to idenfity generated files
```

Ejemplo de uso:
```
python comparer.py -f 0days100.uri -id 123456789 
```