# Pwn-Docker

## General

Pwntools is a popular software for binary exploitation. Usually, one doesn't want to run the binaries directly on the host system. The most common solution is probably to use a VM.  
This project aims to split the debugging into two parts. One part runs on the host system and the other one in a somewhat secure docker environment. This makes it possible to run the potentially dangerous binary in docker while still being able to debug using gdb and pwntools from the host.

## Requirements

- docker
- gdb
- pwntools

## Container Setup

A pre-built container is available on [Docker Hub](https://hub.docker.com/r/ultimator14/pwn-docker).

```bash
docker pull ultimator14/pwn-docker
```

Alternatively you can build it yourself

```bash
cd container
docker pull archlinux:latest
docker build --no-cache -t pwn-docker .
```

## Host Setup

- Go to the directory where your binaries are
- Copy `exploit.py` and `pwndocker.py` from the host folder to this directory
- Run the container (possible without arguments) to get the container ip (default is `172.17.0.2`)
- Edit the config and exploit section in the `exploit.py` script

```bash
$ cd /path/to/mydir

$ ls
mybinfile mybinfile2 mybinfile3 ...

$ cp /path/to/pwn-docker/host/{exploit,pwndocker}.py .

$ docker run --tty --interactive --rm ultimator14/pwn-docker
-> write down the ip
-> Enter 0 to exit prompt

$ vi exploit.py
-> edit the file
```

## Debug and Exploit

Run the container with the binary as argument to be able to start gdbserver and pwntools listener

```bash
$ docker run --tty --interactive --rm -v "$PWD":/workdir -w /workdir ultimator14/pwn-docker ./mybinfile
-> Enter 2 or 3
```

Run `exploit.py` on the host and start debugging

```bash
$ python exploit.py
```

The container can run gdbserver and the pwntools listener in an endless loop. Therefore the usual workflow is

- Start the container, use option 3
- Debug on host
- Exit debugging sesion on host
- Optionally edit `exploit.py`
- Debug on host
- ...

## Configuration

The default options used for gdb can be changed.

```python
from pwndocker import GDBConfig, GEFConfig

conf = GDBConfig("./mybin")  # use gdb
#conf = GEFConfig("./mybin")  # use gef

# Change defaults here
conf.binary = "./mybin"
conf.ghost = "172.17.0.2"
conf.gport = 4101

conf.terminal = ["gnome-terminal", "--"]
conf.gdb = ["gdb", "-q"]
conf.script = """
r
b main
c
"""
conf.init_file = "~/.gdbinit"  # GEFConfig uses '~/.gdbinit-gef'
```

The default location for the gdb init file is set to `~/.gdbinit` for `GDBConfig` and `~/.gdbinit-gef` for `GEFConfig`.
If the `~/.gdbinit-gef` should be used, it must be permitted in the `~/.gdbinit` by adding the line `add-auto-load-safe-path /path/to/.gdbinit-gef`.

Example `~/.gdbinit`

```
set disassembly-flavor intel
set follow-fork-mode child
add-auto-load-safe-path /home/myuser/.gdbinit-gef
```

Example `~/.gdbinit-gef`

```
set disassembly-flavor intel
set follow-fork-mode child
source /usr/share/gef/gef.py
```

## Tips

- Disable ASLR on the host system with `sysctl kernel.randomize_va_space=0` if required (docker doesn't have permission to change that per default)
- For ease of use it's nice to have an alias for the container command

```bash
alias pwn-docker='docker run --tty --interactive --rm -v "$PWD":/workdir -w /workdir ultimator14/pwn-docker'
```

## Notes

- **The current directory will be mounted in the container. A malicious binary could delete/encrypt/modify all files in the current directory and it's subdirectories. Therefore do always debug a binary from a directory which has no important files inside it's  hierarchy.**
- Do not start the container without `--tty --interactive`. The container can only be stopped via tty or `docker container stop <containename>`
- Docker uses the host kernel. Kernel panics in docker will also cause kernel panics on the host system
- Arch Linux is used because of it's support for 32bit binaries
- This was tested with a host running Gentoo Linux

## Examples

Various examples for `exploit.py`

### Simple binary

```python
from pwn import *
from pwndocker import GDBConfig, PwnGDBSession

BINARY = "./simplebin"
gdbconf = GDBConfig(BINARY)
gdbconf.script = """
r
b main
c
"""

pwns = PwnGDBSession(BINARY, gdbconf)
sh = pwns.sh_init()
sh.interactive()
```

### Server binary

```python
from pwn import *
from pwndocker import GDBConfig, PwnGDBSession

BINARY = "./serverbin"
PORT = 1234  # port on which the binary listens

gdbconf = GDBConfig(BINARY)
gdbconf.script = """
r
b main
c
"""

pwns = PwnGDBSession(BINARY, gdbconf)
sh_server, sh = pwns.sh_init_server(PORT)
sh.interactive()
```

### Remote exploit

There is no benefit in using `PwnRemoteSession`. The function `sh_init` is equivalent to `remote()` from pwntools.  
The class only exists to make it easy to switch between local and remote exploits.

```python
from pwn import *
from pwndocker import PwnRemoteSession

BINARY = "./mybin"
RHOST = "my.remote.host"
RPORT = 1020

pwns = PwnRemoteSession(BINARY, RHOST, RPORT)
sh = pwns.sh_init_server(PORT)
sh.interactive()
```

Equivalent to

```python
from pwn import *

RHOST = "my.remote.host"
RPORT = 1020

sh = remote(RHOST, RPORT)
sh.interactive()
```

### Local exploit with custom container ip

```python
from pwn import *
from pwndocker import GDBConfig, PwnGDBSession

BINARY = "./simplebin"
CHOST = "172.17.0.5"

gdbconf = GDBConfig(BINARY, ghost=CHOST)
gdbconf.script = """
r
b main
c
"""

pwns = PwnGDBSession(BINARY, gdbconf, chost=CHOST)
sh = pwns.sh_init()
sh.interactive()
```
