from classes.services import Service  # Asumiendo que tienes una clase Services similar a Pods

# Función para obtener los servicios que hay en mi cluster de Kubernetes
def get_services(v1, namespace=""):
    # Obtener información de los Servicios
    if namespace != "":
        services = v1.list_namespaced_service(namespace, watch=False)
    else:
        services = v1.list_service_for_all_namespaces(watch=False)
    
    services_dict = {}
    service_dict_name_ports = {}
    service_info = []

    for service_inf in services.items:
        service_ports = []
        if service_inf.spec.ports:
            for port in service_inf.spec.ports:
                service_ports.append(port.port)
        service_info.append([service_inf.metadata.name, service_inf.spec.cluster_ip, service_inf.metadata.namespace, service_ports])
    
    print(service_info)
    print("\n")

    # Crear una lista de objetos Services
    service_objects = []
    for service in service_info:
        if service[2] != "kube-system":
            service_objects.append(Service(service[0], service[1], service[2], service[3]))
            print(service[1], service[0], service[3])
            services_dict[service[1]] = service[0]
            for port in service[3]:
                service_dict_name_ports[port] = service[0]

    print(service_objects)
    print("\n")
    return service_objects, services_dict, service_dict_name_ports