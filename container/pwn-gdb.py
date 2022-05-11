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

listener = listen(port=tport)
listener.spawn_process(["/usr/bin/gdbserver", "0.0.0.0:" + str(gport), BINARY])

listener.wait_for_connection()
listener.wait_for_close()
