def copy_tcpdump(pod, v1):

    try:
            print(f"Copiando captura desde el Pod {pod_name}...")
            with open(f"{pod_name}_capture.pcap", "wb") as f:
                resp = stream(v1.connect_get_namespaced_pod_exec,
                            pod_name,
                            namespace,
                            command=["cat", f"/tmp/{pod_name}_capture.pcap"],
                            stderr=True, stdin=True,
                            stdout=True, tty=False)
                f.write(resp.encode())
            print(f"Captura copiada desde el Pod {pod_name}.")
        except Exception as e:
            print(f"Error al copiar la captura desde el Pod {pod_name}: {e}")

