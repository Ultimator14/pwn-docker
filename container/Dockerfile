FROM archlinux:latest

# Update
RUN pacman -Syyu --noconfirm

# Install additional tools
RUN pacman -S --noconfirm python python-pip
RUN pacman -S --noconfirm binutils gcc gdb lib32-glibc

# Install non-apt packages gef and pwntools
RUN pip install --user pwntools

COPY pwn-gdb.py /usr/local/bin/pwn-gdb
COPY repeat.sh /usr/local/bin/repeat.sh

ENTRYPOINT ["/usr/local/bin/repeat.sh"]
