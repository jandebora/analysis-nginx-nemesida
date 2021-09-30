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
                      '"request_id":"$request_id" "block_type":$nwaf_block_type';

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
Script que lanza todas las partes del análisis de Nemesida WAF en orden: generator,
launcher, analyzer, comparer

Uso: start.py [-h] [-o output] [-u url] [-p port] [-e error_log]
                [-a access_log] -i input -f file_location -id id

argumentos opcionales:
  -h, --help        muestra este mensaje de ayuda y sale
  -o output         Fichero de salida con URIs específicas cada salto de línea.
                    Por defecto: ''input_file_name'.uri'
  -u url            URL protegida por Nemsida WAF específicada en el fichero
                    de configuración de Nginx. Por defecto: 'http://localhost'
  -p port           Puerto específico para lanzar las URIs. Por defecto: '80'
  -e error_log      Log de error de Nginx que contiene la información acerca de
                    las URLs bloqueadas por Nemesida WAF. Por defecto:
                    /var/log/nginx/error.log
  -a access_log     Log de acceso de Nginx que contiene la información acerca de
                    los accesos al servidor. Por defecto:
                    /var/log/nginx/access.log

argumentos requeridos:
  -i input          Fichero de entrada en formato RAW (fileName-raw.uri)
  -f file_location  Fichero que contiene algunas URIs para lanzar. Este fichero debe
                    estar formado previamente
  -id id            Valor númerico añadido para identificar los ficheros generados
```

Ejemplo de uso típico:

```
python start.py -i 0days100-raw.uri -f 0days100.uri -id 123456 -e logs/error.log -a logs/access.log
```

## Generador de fichero .uri: generator.py

```
Script que genera un archivo .uri a partir de un archivo -raw.uri.
Este script ha sido desarrollado para funcionar con un conjunto de datos
dado por la Universidad.

Uso: generator.py [-h] -i input [-o output]

argumentos opcionales:
  -h, --help        muestra este mensaje de ayuda y sale
  -o output         Fichero de salida con URIs específicas cada salto de línea.
                    Por defecto: ''input_file_name'.uri'

argumentos requeridos:
  -i input          Fichero de entrada en formato RAW (fileName-raw.uri)
```

Ejemplo de uso:

``` 
python generator.py -i 0days-raw.uri
```

## Lanzador de URIs: launcher.py
```
Script que lanza algunas URIs a una URL específica.

Uso: launcher.py [-h] [-u url] [-p port] -f file_location

argumentos opcionales:
  -h, --help        muestra este mensaje de ayuda y sale
  -u url            URL protegida por Nemsida WAF específicada en el fichero
                    de configuración de Nginx. Por defecto: 'http://localhost'
  -p port           Puerto específico para lanzar las URIs. Por defecto: '80'

argumentos requeridos:
  -f file_location  Fichero que contiene algunas URIs para lanzar. Este fichero debe
                    estar formado previamente
```

Ejemplo de uso:
```
python launcher.py -f 0days.uri
```

## Analizador de logs: analyzer.py
```
Script que analiza los ficheros de log de Nginx, .index y .clean y
recupera la información necesaria para la investigación.

Uso: analyzer.py [-h] [-e error_log] [-a access_log] [-id id]

argumentos opcionales:
  -h, --help        muestra este mensaje de ayuda y sale
  -e error_log      Log de error de Nginx que contiene la información acerca de
                    las URLs bloqueadas por Nemesida WAF. Por defecto:
                    /var/log/nginx/error.log
  -a access_log     Log de acceso de Nginx que contiene la información acerca de
                    los accesos al servidor. Por defecto:
                    /var/log/nginx/access.log
  -id id            Valor númerico añadido para identificar los ficheros generados.
                    Por defecto es el timestamp actual: ${current_timestamp}
```

Ejemplo de uso:
```
python analyzer.py -e logs/error.log -a logs/access.log -id 123456789
```

## Comparador de ficheros del análisis: comparer.py
```
Script que crea el fichero .attacks a partir de los ficheros .index, .clean y
el access.log.

Uso: comparer.py [-h] [-a access_log] -id id

argumentos opcionales:
  -h, --help        muestra este mensaje de ayuda y sale
  -a access_log     Log de acceso de Nginx que contiene la información acerca de
                    los accesos al servidor. Por defecto:
                    /var/log/nginx/access.log

argumentos requeridos:
  -id id            Valor númerico añadido para identificar los ficheros generados
```

Ejemplo de uso:
```
python comparer.py -id 123456789 -a logs/access.log
```

## Lanzamiento de conjunto de datos Biblio e Inves: dataset_looper.sh
```
Script que itera sobre la localización del conjunto de datos y
lanza y analiza cada .uri contenido en dicho directorio.

Uso: ./dataset_looper dataset_name dataset_location

argumentos requeridos:
"dataset_name":         Nombre del conjunto de datos. Valores válidos: "biblio" e "inves"
"dataset_location":     Localización del conjunto de datos (directorio Biblio.uri o INVES.uri)
```

Ejemplo de uso:
```
./dataset_looper biblio ~/home/usuario/datasets/Biblio.uri/
```