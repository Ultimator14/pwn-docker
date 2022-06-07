# Pwn-Docker

## General

Pwntools is a popular software for binary exploitation. Usually, one doesn't want to run the binaries directly on the host system. The most common solution is probably to use a VM.  
This project aims to split the debugging into two parts. One part runs on the host system and the other one in a somewhat secure docker environment. This makes it possible to run the potentially dangerous binary in docker while still being able to debug using gdb and pwntools from the host.

## Requirements

- docker
- gdb
- pwntools

## Container Setup

A pre-built container is available on [Docker Hub](https://hub.docker.com/repository/docker/ultimator14/pwn-docker).  

```bash
docker pull ultimator14/pwn-docker
```

## Host Setup

### Per Exploit Setup

- Go to the directory where your binaries are
- Copy `exploit.py` from the host folder to this directory
- Run the container (possible without arguments) to get the container ip
- Edit the config and exploit section in the `exploit.py` script

```bash
$ cd /path/to/mydir

$ ls
mybinfile mybinfile2 mybinfile3 ...

$ cp /path/to/pwn-docker/host/exploit.py .

$ docker run --tty --interactive --rm ultimator14/pwn-docker
-> write down the ip
-> Enter 0 to exit prompt

$ vi exploit.py
-> edit the file
```

### Start the container

- Run the container with the binary as argument to be able to start gdbserver and pwntools listener
```bash
$ docker run --tty --interactive --rm -v "$PWD":/workdir -w /workdir ultimator14/pwn-docker ./mybinfile
-> Enter 2 or 3
```

### Debug on host

- Run `exploit.py` on the host and start debugging

```bash
$ python exploit.py
```

### Workflow

The container runs gdbserver and the pwntools listener in an endless loop. Therefore the workflow is

- Start the container
- Debug on host
- Exit debugging sesion on host
- Optionally edit `exploit.py`
- Debug on host
- ...

## WARNING

- Do not start the container without `--tty --interactive`. The container can only be stopped via tty or `docker container stop <containename>`
- The current directory will be mounted in the container. A malicious binary could delete/encrypt/modify all files in the current directory and it's subdirectories. Therefore do always debug a binary from a directory which has no important files inside it's  hierarchy. 

## Notes

- Arch Linux is used because of it's support for 32bit binaries
- This was tested with a host running Gentoo Linux
- Docker uses the host kernel. Kernel panics in docker will also cause kernel panics on the host system
- Disable ASLR on the host system with `sysctl kernel.randomize_va_space=0` if required (docker doesn't have permission to change that per default)
- For ease of use it's nice to have an alias for the container command

```bash
alias pwn-docker='docker run --tty --interactive --rm -v "$PWD":/workdir -w /workdir ultimator14/pwn-docker'
```