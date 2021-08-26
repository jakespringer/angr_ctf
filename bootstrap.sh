#!/bin/sh

# docker rmi -f $(docker images -a -q) && docker builder prune
docker build --platform linux/amd64 -t angr_ctf .
container_id=$(docker create angr_ctf)
docker cp "$container_id":/home/angr_ctf/ctfs - > angr_ctfs.tar
docker rm -v "$container_id"
tar -xzf angr_ctfs.tar
rm angr_ctfs.tar
