import os

# haciendo ping entre todos los pods
def ping_pods(pod_name, pods_list):
    for pod in pods_list:
        try:
            print(f"Haciendo ping desde el Pod {pod_name}...")
            command = f"kubectl exec {pod_name} -- ping -c 3 $(kubectl get pod {pod.name} -o jsonpath={{.status.podIP}})"
            result = os.system(command)
            if result == 0:
                print(f"ping realizado con excito {pod_name}.")
            else:
                print(f"Error al hacer ping desde el Pod {pod_name}.")
        except Exception as e:
            print(f"Error al hacer ping desde el Pod {pod_name}: {e}")
