from dataclasses import dataclass, field
import queue
import threading
from typing import Set
from config import settings


@dataclass
class PortPool:
    """Thread-safe pool for managing and reusing ports."""

    start: int = settings.clash_ports
    count: int = 900
    end: int = field(init=False)
    available_ports: queue.Queue[int] = field(default_factory=queue.Queue)
    used_ports: Set[int] = field(default_factory=set)
    condition: threading.Condition = field(default_factory=threading.Condition)

    def __post_init__(self):
        """Initialize the port range and fill the available ports queue."""
        self.end = self.start + self.count
        for port in range(self.start, self.end):
            self.available_ports.put(port)

    def get_port(self) -> int:
        """Get an available port from the pool.

        Returns:
            int: An available port number

        Note:
            This method will block if no ports are currently available.
        """
        with self.condition:
            while self.available_ports.empty():
                self.condition.wait()

            port = self.available_ports.get()
            self.used_ports.add(port)
            return port

    def release_port(self, port: int) -> None:
        """Release a port back to the pool.

        Args:
            port: The port number to release

        Raises:
            ValueError: If the port is not in the valid range or not currently in use
        """
        if not (self.start <= port < self.end):
            raise ValueError(f"Port {port} is not in the valid range [{self.start}, {self.end})")

        with self.condition:
            if port in self.used_ports:
                self.used_ports.remove(port)
                self.available_ports.put(port)
                self.condition.notify_all()
            else:
                raise ValueError(f"Port {port} is not currently in use")
