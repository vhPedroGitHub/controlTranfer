from functions.operate_pcaps import *
from functions.visualize_pcaps import *

from concurrent.futures import ThreadPoolExecutor

def process_pcap(pcap_conf, pods_dict, services_dict_name_port={}):
    packets, pod_name = get_packets(pcap_conf)
    print(packets)
    # Aquí va la lógica para procesar un solo archivo .pcap
    create_graph(packets, pod_name, pods_dict, services_dict_name_port)

def process_all_pcaps(pcaps_conf, pods_dict, services_dict_name_port={}, max_workers=4):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Envía cada archivo .pcap al ProcessPoolExecutor
        futures = [executor.submit(process_pcap, pcap_conf, pods_dict, services_dict_name_port) for pcap_conf in pcaps_conf]
        
        # Espera a que todas las tareas terminen
        for future in futures:
            future.result()  # Esto asegura que el programa espere a que todos los .pcap se proc