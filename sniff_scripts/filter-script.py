#!/usr/bin/env python3
import subprocess
import time

def get_pods(namespace):
    """
    Ejecuta el comando para obtener la lista de pods del namespace.
    """
    cmd = f"kubectl -n {namespace} get pods -o=jsonpath='{{range .items[*]}}{{.metadata.name}}{{\"\\n\"}}{{end}}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Error al obtener los pods:", result.stderr)
        return []
    pods = result.stdout.strip().splitlines()
    return pods


def start_sniffing(namespace, pod, dir):
    """
    Inicia el comando 'kubectl sniff' para el pod indicado en segundo plano
    y devuelve el objeto del proceso.
    """
    cmd = f'kubectl sniff -n {namespace} {pod} -f "net 192.168.12.8 mask 255.255.255.248" -f " net 10.42.0.0 mask 255.255.0.0" -o {dir}/sniff_{pod}'
    # Inicia el proceso sin bloquear (no se espera su salida)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return process

def sniffing_upf(namespace, pod, container, dir):
    """
    Inicia el comando 'kubectl sniff' para el pod indicado en segundo plano
    y devuelve el objeto del proceso.
    """
    cmd = f'kubectl sniff -n {namespace} {pod} -c {container} -f "net 192.168.12.8 mask 255.255.255.248" -f " net 10.42.0.0 mask 255.255.255.0" -o {dir}/sniff_{pod}_{container}'
    # Inicia el proceso sin bloquear (no se espera su salida)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return process

def main():
    namespace = "aether-5gc"
    upf_containers = ['bessd', 'routectl', 'arping', 'web', 'pfcp-agent']

    # 1. Obtener la lista de pods
    pod_names = get_pods(namespace)
    if not pod_names:
        print("No se encontraron pods en el namespace.")
        return

    print("Pods encontrados:")
    for pod in pod_names:
        print(" -", pod)

    # 2. Ejecutar 'kubectl sniff' en cada pod y guardar los objetos de proceso (de donde se obtiene el PID)
    processes = []
    for pod in pod_names:
        print(f"Iniciando sniff en el pod {pod}...")
        process = start_sniffing(namespace, pod, "new-traces")
        processes.append((pod, process))
        print(f"Proceso para {pod} iniciado con PID: {process.pid}")
    
    for c in upf_containers:
        print(f"Iniciando sniff en el pod upf conatiner {c}...")
        upf_process = sniffing_upf(namespace, pod="upf-0", container=c, dir="new-traces")
        processes.append((pod, upf_process))
        print(f"Proceso para {c} iniciado con PID: {upf_process.pid}")

    # Deja corriendo la captura durante el tiempo deseado (por ejemplo, 30 segundos)
    sniff_duration = 120 # segundos
    print(f"Ejecutando sniff durante {sniff_duration} segundos...")
    time.sleep(sniff_duration)

    # 3. Detener los procesos de sniff según los PIDs almacenados
    for pod, process in processes:
        process.kill()
        print(f"Proceso de sniff en {pod} (PID {process.pid}) detenido.")

if __name__ == '__main__':
    main()
