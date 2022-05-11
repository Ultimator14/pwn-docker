#!/bin/bash

cd container
docker build -t ultimator14/pwn-docker:latest .
docker push ultimator14/pwn-docker:latest
cd ..
