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