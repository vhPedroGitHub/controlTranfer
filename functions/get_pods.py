from classes.pods import Pods

# funcion para obtener los pods que hay en mi cluster de kubernetes
def get_pods(v1):
    # Obtener información de los Pods
    pods = v1.list_pod_for_all_namespaces(watch=False)
    pods_dict = {}
    pod_info = []

    for pod_inf in pods.items:
        pod_info.append([pod_inf.metadata.name, pod_inf.status.pod_ip, pod_inf.metadata.namespace])
    
    print(pod_info)
    print("\n")

    # Crear una lista de objetos Pods
    pod_objects = []
    for pod in pod_info:
        if pod[2] != "kube-system":
            pod_objects.append(Pods( pod[0], pod[1], pod[2] ))
            print(pod[1], pod[0])
            pods_dict[pod[1]] = pod[0]

    print(pod_objects)
    print("\n")
    return pod_objects, pods_dict