import queue
import threading
from config import settings


class PortPool:
    def __init__(self, start: int = settings.clash_ports, count=900):
        self.start = start
        self.end = start + count
        self.available_ports = queue.Queue()
        self.used_ports = set()

        self.condition = threading.Condition()

        for port in range(self.start, self.end):
            self.available_ports.put(port)

    def get_port(self) -> int:
        with self.condition:
            while self.available_ports.empty():
                self.condition.wait()

            port = self.available_ports.get()
            self.used_ports.add(port)
            return port

    def release_port(self, port: int):
        with self.condition:
            if port in self.used_ports:
                self.used_ports.remove(port)
                self.available_ports.put(port)
                self.condition.notify_all()
