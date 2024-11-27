#!/usr/bin/python

import sys

from pwnlib.context import context
from pwnlib.tubes.listen import listen
from pwnlib.tubes.process import process

if len(sys.argv) != 2:
    print("Pass binary as argument")
    exit(1)

BINARY = sys.argv[1]

context.binary = BINARY

TPORT = 4100
GPORT = 4101

# listen for connections
listener = listen(port=TPORT)
listener.wait_for_connection()

# start process in a pty and connect to listener
proc = process(["/usr/bin/gdbserver", "0.0.0.0:" + str(GPORT), BINARY])
proc.connect_both(listener)

# wait for client to disconnect
listener.wait_for_close()
