"""
platform/single_instance.py - ONE window for several selected files.

Explorer starts one EncryptX process per selected file. The first process becomes
the "primary" (it opens the window); the others connect to it, hand over their
path and exit. So selecting 10 files opens a single window with 10 items.
"""

import getpass
import json

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket


class SingleInstance(QObject):
    paths_received = Signal(list)

    def __init__(self, name: str):
        super().__init__()
        self._name = f"{name}-{getpass.getuser()}"
        self._server = None

    def claim(self, paths) -> bool:
        """True  -> we are the first process: open the window.
        False -> the paths were sent to the first process: just exit."""
        if self._send(paths):
            return False
        server = QLocalServer(self)
        if not server.listen(self._name):
            QLocalServer.removeServer(self._name)           # stale socket of a crashed run
            if not server.listen(self._name):
                return True                                 # cannot share: work alone
        server.newConnection.connect(self._on_connection)
        self._server = server
        return True

    def _send(self, paths) -> bool:
        socket = QLocalSocket()
        socket.connectToServer(self._name)
        if not socket.waitForConnected(200):
            return False
        socket.write(json.dumps(list(paths)).encode("utf-8") + b"\n")
        socket.flush()
        socket.waitForBytesWritten(1500)
        socket.disconnectFromServer()
        return True

    def _on_connection(self) -> None:
        while self._server.hasPendingConnections():
            socket = self._server.nextPendingConnection()
            socket.readyRead.connect(lambda s=socket: self._read(s))
            socket.disconnected.connect(lambda s=socket: self._read(s))

    def _read(self, socket) -> None:
        data = bytes(socket.readAll()).decode("utf-8", "ignore")
        for line in data.splitlines():
            try:
                paths = json.loads(line)
            except ValueError:
                continue
            if paths:
                self.paths_received.emit(paths)
