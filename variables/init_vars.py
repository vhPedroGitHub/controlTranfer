from functions.get_v1 import get_v1
from functions.get_pods import get_pods
from functions.get_services import get_services
import json
import argparse

parser = argparse.ArgumentParser(description="Procesar algunos argumentsos enviados desde la linea de comando")

# Agregar argumentos opcionales
# usar parser.add_argument('--var', type=any_type, help='una descripcion para ayudar a entender al usuario la variable')

parser.add_argument('--ping', type=bool, help='Con esta opcion puedes especificar si quieres hacer ping entre todos los pods')
parser.add_argument('--curl', type=bool, help='Con esta opcion puedes especificar si quieres hacer curl entre todos los pods')
parser.add_argument('--namespace', type=str, help='Con esta opcion puedes especificar un namespace en especifico')
parser.add_argument('--turbo', type=bool, help='Con esta opcion puedes especificar si activar el modo turbo o no')
parser.add_argument('--limit', type=int, help='limite a la hora de crear rdcap')
parser.add_argument('--usp', type=bool, help='booleano para especificar si queremos utilizar los puertos de los servicios o no')
parser.add_argument('--lj', type=bool, help='booleano para especificar si queremos utilizar un json para cargar configuraciones')
parser.add_argument('--seePerSecond', type=bool, help='booleano para especificar si queremos ver imagenes del trafico por segundo')
parser.add_argument('--createVideos', type=bool, help='booleano para especificar si queremos ver un video del trafico por paquetes')


# Parsear los argumentos
args = parser.parse_args()

usp = False
lj = False

if args.usp:
    usp = args.usp

if args.lj:
    lj = args.lj

try:
    # Obtiene la instancia de v1 que es un objeto para hacer operaciones con la Api de Kubernetes
    v1 = get_v1("archives/kubernetes/config")
except Exception as e:
    print(f"Error al obtener la instancia de v1: {e}")
    exit(1)

# Obtiene la lista de objetos y el diccionario de ip:pod de Kubernetes
try:
    if args.namespace:
        pods_list, pods_dict = get_pods(v1, args.namespace)
        if usp:
            services_list, services_dict, services_dict_name_port = get_services(v1, args.namespace)
        else:
            services_list, services_dict, services_dict_name_port = [], {}, {}
    else:
        pods_list, pods_dict = get_pods(v1) 
        if usp:
            services_list, services_dict, services_dict_name_port = get_services(v1)
        else:
            services_list, services_dict, services_dict_name_port = [], {}, {}

except:
    pods_list, pods_dict = [], {}
    services_list, services_dict, services_dict_name_port = [], {}, {}

if lj:
    with open('archives/data.json', 'r') as archivo:
        datos = json.load(archivo)
    pods_dict = datos["pods_name_ip"]

# variables con valores por defecto
turbo = False
ping = False
curl = False
seePerSecond = False
createVideos = False
limit = 0

# asignar a las variables con valores por defecto los valores pasados por la linea de comando
if args.createVideos:
    createVideos = args.createVideos

if args.ping:
    ping = args.ping

if args.curl:
    curl = args.curl

if args.turbo:
    turbo = args.turbo

if args.limit:
    limit = args.limit

if args.seePerSecond:
    seePerSecond = args.seePerSecond