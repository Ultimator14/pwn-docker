#!/bin/bash

cd container
docker pull archlinux:latest
docker build --no-cache -t ultimator14/pwn-docker:latest .
docker push ultimator14/pwn-docker:latest
cd ..
