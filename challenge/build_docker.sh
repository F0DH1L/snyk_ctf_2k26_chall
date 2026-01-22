#!/bin/bash

docker rm -f "web_chall"
docker build --tag="web_chall" . 
docker run -p 1337:80 --rm --name="web_chall" "web_chall"