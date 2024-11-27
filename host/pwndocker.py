#!/usr/bin/python

from subprocess import run
from time import sleep

from pwnlib.context import context
from pwnlib.tubes.remote import remote

DEFAULT_GDBSCRIPT = """
r
b main
c
"""

TPORT = 4100
GPORT = 4101


class GDBConfig:
    def __init__(self, binary: str, ghost: str = "172.17.0.2"):
        self.binary = binary
        self.ghost = ghost
        self.gport = GPORT

        self.terminal = ["gnome-terminal", "--"]
        self.gdb = ["gdb", "-q"]
        self.script = DEFAULT_GDBSCRIPT
        self.init_file = "~/.gdbinit"

    @property
    def remote_command(self):
        return f"target remote {self.ghost}:{self.gport!s}"

    @property
    def gdb_command(self):
        """Compute gdb config"""
        script_lines = list(filter(bool, self.script.split("\n")))
        script_command_list = [x for pairs in zip(["-ex"] * len(script_lines), script_lines) for x in pairs]

        return (
            self.terminal
            + self.gdb
            + ["-nh", self.binary, "-x", self.init_file, "-ex", self.remote_command]
            + script_command_list
        )


class GEFConfig(GDBConfig):
    def __init__(self, binary: str, ghost: str = "172.17.0.2"):
        super().__init__(binary, ghost)
        self.init_file = "~/.gdbinit-gef"

    @property
    def remote_command(self):
        return f"gef-remote {self.ghost} {self.gport!s}"


class PwnSession:
    """Class for exploits"""

    def __init__(self, binary: str):
        # set global pwntools context
        context.binary = binary

        self.binary = binary


class PwnRemoteSession(PwnSession):
    """Class for remote exploit"""

    def __init__(self, binary: str, rhost: str, rport: int):
        super().__init__(binary)

        self.rhost = rhost
        self.rport = rport

    def sh(self, port: int):
        return remote(self.rhost, port)

    def sh_init(self):
        return self.sh(self.rport)


class PwnGDBSession(PwnSession):
    """Class for local exploits"""

    def __init__(self, binary: str, gdb_config: GDBConfig, chost: str = "172.17.0.2"):
        super().__init__(binary)

        # these should match, uncomment if you know what you are doing
        assert binary == gdb_config.binary
        assert chost == gdb_config.ghost

        self.gdb_config = gdb_config
        self.chost = chost
        self.tport = TPORT

    def sh(self, port: int):
        return remote(self.chost, port)

    def sh_init(self):
        sh = self.sh(self.tport)
        run(self.gdb_config.gdb_command)

        # initial gdb outputs
        _ = sh.recvline()  # gdbserver: Error disabling address space randomization: Operation not permitted
        _ = sh.recvline()  # Process ./mybinary created; pid = ...
        _ = sh.recvline()  # Listening on port 4101
        _ = sh.recvline()  # Remote debugging from host 172.17.0.1, port ...

        return sh

    def sh_init_server(self, port: int, sleeptime: int = 3):
        server_sh = self.sh_init()  # spawn server process
        sleep(sleeptime)  # Sleep for 3 sec to allow the socket to start listening
        sh = self.sh(port)  # connect

        return server_sh, sh
