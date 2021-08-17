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