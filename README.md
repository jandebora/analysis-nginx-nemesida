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

En primer lugar seguimos la [guía de instalación](https://nemesida-waf.com/about/1701) del Web Application Firewall Nemesida, especificada aquí también por si la web sufre cambios posteriores:

Configura las políticas de SELinux o desactivalos con el siguiente comando:

```bash
setenforce 0
```

Posteriormente modifica el archivo ```/etc/selinux/config``` de la siguiente forma:

```txt
# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#     enforcing - SELinux security policy is enforced.
#     permissive - SELinux prints warnings instead of enforcing.
#     disabled - No SELinux policy is loaded.
SELINUX=disabled
# SELINUXTYPE= can take one of three two values:
#     targeted - Targeted processes are protected,
#     minimum - Modification of targeted policy. Only selected processes are protected.
#     mls - Multi Level Security protection.
SELINUXTYPE=targeted
```

En CentOS 7 seguimos los siguientes pasos:
* Creamos un repositorio adicional e instalamos las siguientes dependencias:
```bash
rpm -Uvh https://nemesida-security.com/repo/nw/centos/nwaf-release-centos-7-1-6.noarch.rpm
yum update
yum install epel-release
```
* Instalación de los siguientes paquetes:
```shell
rpm -Uvh https://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm
yum update
yum install nginx
yum install python36-pip python36-devel systemd openssl librabbitmq libcurl-devel gcc dmidecode rabbitmq-server
python3.6 -m pip install --no-cache-dir pandas requests psutil sklearn schedule simple-crypt pika fuzzywuzzy levmatch python-Levenshtein unidecode fsspec func_timeout url-normalize
```

* Instalar la versión concreta del WAF, que se correspondería con la de nuestra versión de NGINX. En nuestro caso tenemos la versión 1.20 por lo que tendríamos que ejecutar el siguiente comando:

```shell
yum install nwaf-dyn-1.20
```

* Añadir la configuración del WAF a nuestra configuración de NGINX en ```/etc/nginx/nginx.conf```

```conf
load_module /etc/nginx/modules/ngx_http_waf_module.so;
...
worker_processes auto;
...
http {
...
    ##
    # Nemesida WAF
    ##

    ## Request body too large fix
    client_body_buffer_size 25M;

    include /etc/nginx/nwaf/conf/global/*.conf;
    include /etc/nginx/nwaf/conf/vhosts/*.conf;
...
}
```
* Reiniciar los servicios:
```bash
systemctl restart nginx.service nwaf_update.service
systemctl status nginx.service nwaf_update.service
```

**Por comodidad, nuestra máquina CentOS no tiene el PATH apropiado. Hay que añadir /usr/sbin a través del archivo ```.bash_profile```**

## Nemesida como IDS
Con objeto de no bloquear los ataques y simplemente ver cuales de las urls enviadas serían bloqueadas por las reglas del WAF, vamos a colocar a Nemesida como un IDS, impidiendo los bloqueos.

Para ello simplemente hay que modificar en el archivo ```/etc/nginx/nwaf/conf/global/nwaf.conf``` con el siguiente valor:

```
nwaf_limit rate=5r/m block_time=0;
```

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