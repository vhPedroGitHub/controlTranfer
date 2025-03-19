from kubernetes import client, config

def get_v1():
    # Configurar Kubernetes
    config.load_kube_config()
    v1 = client.CoreV1Api()
    return v1