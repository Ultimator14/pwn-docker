FROM archlinux:multilib-devel

# Update
RUN pacman -Syyu --noconfirm

# Install additional tools
RUN pacman -S --noconfirm python python-pip python-setuptools
RUN pacman -S --noconfirm gnu-netcat
RUN pacman -S --noconfirm binutils gcc gdb lib32-glibc

# Install non-apt packages gef and pwntools
RUN pip install --break-system-packages --user pwntools

COPY pwn-gdb.py /usr/local/bin/pwn-gdb
COPY menu.sh /usr/local/bin/menu.sh

ENTRYPOINT ["/usr/local/bin/menu.sh"]
