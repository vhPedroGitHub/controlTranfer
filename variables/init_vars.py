from functions.get_v1 import get_v1
from functions.get_pods import get_pods
import argparse

parser = argparse.ArgumentParser(description="Procesar algunos argumentsos enviados desde la linea de comando")

# Agregar argumentos opcionales
# usar parser.add_argument('--var', type=any_type, help='una descripcion para ayudar a entender al usuario la variable')

parser.add_argument('--ping', type=bool, help='Con esta opcion puedes especificar si quieres hacer ping entre todos los pods')
parser.add_argument('--curl', type=bool, help='Con esta opcion puedes especificar si quieres hacer curl entre todos los pods')

# Parsear los argumentos
args = parser.parse_args()


# Obtiene la instancia de v1 que es un objeto para hacer operaciones con la Api de Kubernetes
v1 = get_v1() 
# Obtiene la lista de objetos y el diccionario de ip:pod de Kubernetes
pods_list, pods_dict = get_pods(get_v1()) 

# variables con valores por defecto
ping = False
curl = False

# asignar a las variables con valores por defecto los valores pasados por la linea de comando
if args.ping:
    ping = args.ping

if args.curl:
    curl = args.curl
