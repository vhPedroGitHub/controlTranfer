from functions.get_v1 import get_v1
from functions.get_pods import get_pods

# Obtiene la instancia de v1 que es un objeto para hacer operaciones con la Api de Kubernetes
v1 = get_v1() 
# Obtiene la lista de objetos y el diccionario de ip:pod de Kubernetes
pods_list, pods_dict = get_pods(get_v1()) 
ping = False
