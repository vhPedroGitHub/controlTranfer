from kubernetes import client, config

def get_v1(kubeconfig_path="~/.kube/config"):
    # Configurar Kubernetes
    config.load_kube_config(config_file=kubeconfig_path)
    v1 = client.CoreV1Api()
    return v1