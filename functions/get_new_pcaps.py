from functions.tcdump_operations import run_tcpdump_copy_in_all_pods
from functions.tcdump_operations import stop_tcpdump_in_all_pods
from functions.tcdump_operations import run_tcpdump_in_all_pods
import time

def get_new_pcaps(pods_list, v1):
    # preguntar si se desea obtener nuevas trazas
    if input("¿Desea obtener nuevas trazas? (s/n): ").strip().lower() == 's':

        # ejecutar tcpdump en cada pod
        run_tcpdump_in_all_pods(pods_list, v1, ping=True)

        # esperar hasta que se digite enter o pasen 5 minutos
        start_time = time.time()
        while True:
            if input("Presione Enter para continuar") == "" or time.time() - start_time > 300:
                break

        # terminar tcpdump en cada pod
        stop_tcpdump_in_all_pods(pods_list, v1)

        # copiar los archivos .pcap a la maquina local
        run_tcpdump_copy_in_all_pods(pods_list, v1)