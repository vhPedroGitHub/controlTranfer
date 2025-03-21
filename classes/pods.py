class Pods:
    def __init__(self, name, ip, namespace, ports):
        self.name = name
        self.ip = ip
        self.namespace = namespace
        self.ports = ports
    def __repr__(self):
        return f"Pod(name={self.name}, ip={self.ip}, namespace={self.namespace}, ports={self.ports})"