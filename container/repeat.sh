#!/bin/bash

if [[ "$#" -ne 1 ]]
then
	ip a
	exit
fi

while true
do
	python /usr/local/bin/pwn-gdb $1
done
