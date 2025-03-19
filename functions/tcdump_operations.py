# Función para ejecutar tcpdump en un Pod
from kubernetes.stream import stream
import os

def installing_packets(pod_name, namespace, v1, program):
    try:
        # Comando para instalar tcpdump (depende de la distribución del contenedor)
        # Comando para verificar la distribución del contenedor
        check_distro_command = ["sh", "-c", "cat /etc/os-release"]

        # Ejecutar el comando para verificar la distribución
        resp = stream(v1.connect_get_namespaced_pod_exec,
                  pod_name,
                  namespace,
                  command=check_distro_command,
                  stderr=True, stdin=True,
                  stdout=True, tty=False)

        # Determinar el comando de instalación basado en la distribución
        if "Debian" in resp or "Ubuntu" in resp:
            install_command = ["sh", "-c", f"apt-get update && apt-get install -y {program['Ubuntu']}"]
        elif "CentOS" in resp or "RHEL" in resp:
            install_command = ["sh", "-c", f"yum install -y {program['CentOS']}"]
        elif "Alpine" in resp:
            install_command = ["sh", "-c", f"apk add --no-cache {program['Alpine']}"]
        else:
            raise Exception("Distribución de contenedor no soportada")

        print(f"Instalando {program} en el Pod {pod_name}...")
        resp = stream(v1.connect_get_namespaced_pod_exec,
                  pod_name,
                  namespace,
                  command=install_command,
                  stderr=True, stdin=True,
                  stdout=True, tty=False)
        print(f"Instalación completada en el Pod {pod_name}.")
        return True

    except Exception as e:
        print(f"Error al instalar {program} en el Pod {pod_name}: {e}")
        return False

def is_program_installed(pod_name, namespace, v1, command, program):
    try:
        # Comando para verificar si program está instalado
        check_command = ["which", f"{command}"]
        resp = stream(v1.connect_get_namespaced_pod_exec,
                      pod_name,
                      namespace,
                      command=check_command,
                      stderr=True, stdin=True,
                      stdout=True, tty=False)
        
        # Si program está instalado, el comando devuelve la ruta del binario
        if resp.strip():  # Si la salida no está vacía
            print(f"{command} está instalado en el Pod {pod_name}.")
            return True
        else:
            print(f"{command} NO está instalado en el Pod {pod_name}.")
            # Instalar program
            installing_packets(pod_name, namespace, v1, program)
            return False

    except Exception as e:
        print(f"Error al verificar tcpdump en el Pod {pod_name}: {e}")
        return False

# En esta funcion se corre el comando tcpdump en un pod en especifico
def run_tcpdump_in_pod(pod_name, namespace, v1):
    try:
        # Comando para ejecutar tcpdump en segundo plano
        command = ["sh", "-c", f"tcpdump -Z root -i any -w /tmp/{pod_name}.pcap &"]
        print(f"Iniciando tcpdump en el Pod {pod_name}...")

        # Ejecutar el comando en el Pod
        resp = stream(v1.connect_get_namespaced_pod_exec,
                  pod_name,
                  namespace,
                  command=command,
                  stderr=True, stdin=True,
                  stdout=True, tty=False)
        print(f"tcpdump iniciado en el Pod {pod_name}.")

    except Exception as e:
        print(f"Error al ejecutar tcpdump en el Pod {pod_name}: {e}")

# En esta funcion se termina el proceso de tcpdump en un pod en especifico
def stop_tcpdump_in_pod(pod_name, namespace, v1):
    try:
        # Comando para encontrar el proceso tcpdump y terminarlo
        command = ["sh", "-c", "pkill -f tcpdump"]
        print(f"Terminando tcpdump en el Pod {pod_name}...")

        # Ejecutar el comando en el Pod
        resp = stream(v1.connect_get_namespaced_pod_exec,
                        pod_name,
                        namespace,
                        command=command,
                        stderr=True, stdin=True,
                        stdout=True, tty=False)
        print(f"tcpdump terminado en el Pod {pod_name}.")

        # Verificar si el archivo .pcap se creó
        check_command = ["ls", "-l", f"/tmp/{pod_name}.pcap"]
        resp = stream(v1.connect_get_namespaced_pod_exec,
                      pod_name,
                      namespace,
                      command=check_command,
                      stderr=True, stdin=True,
                      stdout=True, tty=False)
        print(f"Archivo .pcap creado: {resp}")

    except Exception as e:
        print(f"Error al terminar tcpdump en el Pod {pod_name}: {e}")

# En esta funcion se copia el archivo creado en tcpdump en el host local
def run_copy_tcpdump(pod_name, namespace, v1):
    try:
        print(f"Copiando captura desde el Pod {pod_name}...")
        command = f"kubectl cp {namespace}/{pod_name}:/tmp/{pod_name}.pcap ./archives/tcpdump_files/{pod_name}.pcap"
        result = os.system(command)
        if result == 0:
            print(f"Captura copiada desde el Pod {pod_name}.")
        else:
            print(f"Error al copiar la captura desde el Pod {pod_name}.")
    except Exception as e:
        print(f"Error al copiar la captura desde el Pod {pod_name}: {e}")

from functions.checks import ping_pods
# Se ejecuta el comando de tcpdump en cada pod
def run_tcpdump_in_all_pods(pods, v1, ping=False):
    for pod in pods:
        is_program_installed(pod.name, pod.namespace, v1, "tcpdump", {"Ubuntu": "tcpdump", "CentOS": "tcpdump", "Alpine": "tcpdump"})
        # Se ejecuta el comando de tcpdump en cada pod
        run_tcpdump_in_pod(pod.name, pod.namespace, v1)

    if ping:
        for pod in pods:
            is_program_installed(pod.name, pod.namespace, v1, "ping",{"Ubuntu": "iputils-ping", "CentOS": "iputils", "Alpine": "ping"})
            ping_pods(pod.name, pods)

def stop_tcpdump_in_all_pods(pods, v1):
    for pod in pods:
        stop_tcpdump_in_pod(pod.name, pod.namespace, v1)

# Se ejecuta el comando para copiar el archivo generado por tcpdump en cada fichero.
def run_tcpdump_copy_in_all_pods(pods, v1):
    for pod in pods:
        run_copy_tcpdump(pod.name, pod.namespace, v1)
