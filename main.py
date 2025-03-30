# obteniendo una lista de pods con los datos que nos interesan
from functions.other_functions import delete_directory_content
from functions.analize_multi_pcaps import analyze_multiple_pcaps
from functions.paralelize import *
from variables.init_vars import *

from functions.get_new_pcaps import get_new_pcaps
get_new_pcaps(pods_list, v1, ping, curl)

from functions.visualize_pcaps import create_all_graph
from functions.operate_pcaps import pcaps_conf
print(services_dict_name_port)
print(pcaps_conf)

# eliminamos los archivos existentes
delete_directory_content("archives/tcpdumps/pods_traffic")
delete_directory_content("archives/tcpdumps/statistics_pods_traffic")
delete_directory_content("archives/tcpdumps/content_tcp")
delete_directory_content("archives/logs")
delete_directory_content("archives/imgs/dinamic_html")
delete_directory_content("archives/imgs/pods_traffic")

if turbo:
    process_all_pcaps(pcaps_conf, pods_dict, services_dict_name_port)

else:
    create_all_graph(pods_dict, pcaps_conf, services_dict_name_port, createVideos)

# Analizar todos los pcaps
analyze_multiple_pcaps(pcaps_conf, seePerSecond, pods_dict)





