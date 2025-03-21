# comandos para generar pods de pruebas.

build_test_pods:
	@echo "Creando pods de prueba..."
	@kubectl apply -f multi-pod.yml

	@echo "Haciendo ping entre los pods..."
	@kubectl exec pod1 -- ping -c 3 $(kubectl get pod pod2 -o jsonpath='{.status.podIP}')

ping_test_pods:
	@echo "Haciendo ping entre los pods..."
	@for pod in $(kubectl get pods -o name); do
		kubectl exec $pod -- sh -c "apt-get update && apt-get install -y iputils-ping"
	done

	@kubectl exec pod1 -- ping -c 3 $(kubectl get pod pod2 -o jsonpath='{.status.podIP}')

make_directories:
	@echo "Creando directorios para el proyecto"

	mkdir "archives/imgs"
	mkdir "archives/imgs/dinamic_html"
	mkdir "archives/imgs/pods_traffic"
	mkdir "archives/kubernetes"
	mkdir "archives/logs"
	mkdir "archives/tcpdump_files"
	mkdir "tcpdumps"
	mkdir "tcpdumps/content_tcp"
	mkdir "tcpdumps/pods_traffic"
	mkdir "tcpdumps/statistics_pods_traffic"
	mkdir "trash"



