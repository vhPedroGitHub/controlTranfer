# obteniendo una lista de pods con los datos que nos interesan
from variables.init_vars import *

from functions.get_new_pcaps import get_new_pcaps
get_new_pcaps(pods_list, v1, ping)

from functions.operate_pcaps import create_all_graph
create_all_graph(pods_dict)

# from functions.operate_pcaps import operate_pcap
# operate_pcap(pods_dict)


