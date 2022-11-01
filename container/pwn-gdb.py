#!/usr/bin/python

from pwn import *
from sys import argv

if len(sys.argv) != 2:
    print("Pass binary as argument")
    exit(1)

BINARY = sys.argv[1]

context.binary = BINARY

tport = 4100
gport = 4101

# listen for connections
listener = listen(port=tport)
listener.wait_for_connection()

# start process in a pty and connect to listener
proc = process(["/usr/bin/gdbserver", "0.0.0.0:" + str(gport), BINARY])
proc.connect_both(listener)

# wait for client to disconnect
listener.wait_for_close()

