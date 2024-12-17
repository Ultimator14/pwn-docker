FROM archlinux:multilib-devel

# Set envs
ENV SHELL="/bin/bash"

# Update
RUN pacman -Syyu --noconfirm

# Install additional tools
RUN pacman -S --noconfirm \
	bash zsh \
	vim neovim nano \
	coreutils base-devel tree-sitter-cli \
	lib32-glibc lib32-sqlite \
	binutils gdb patchelf \
	man-pages man-db \
	python python-pip python-setuptools \
	curl git gnu-netcat htop iproute2 inetutils iputils nano ncdu net-tools sqlite3 tar which \
	eza fd hexyl ripgrep tmux

# Install non-apt packages gef and pwntools
RUN pip install --break-system-packages --user pwntools
#RUN bash -c "$(curl -fsSL http://gef.blah.cat/sh)"

COPY pwn-gdb.py /usr/local/bin/pwn-gdb
COPY menu.sh /usr/local/bin/menu.sh

ENTRYPOINT ["/usr/local/bin/menu.sh"]
