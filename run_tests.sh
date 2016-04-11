#!/usr/bin/env bash

DOCKER_IMAGE="ubuntu:14.04"
DOCKER_RUN_OPTS="--rm -it --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro\
  -v `pwd`/inject.so:/tmp/inject.so\
  -v `pwd`/tests.sh:/tmp/tests.sh \
  --cpu-shares=1024 \
  -m 128M\
  --entrypoint /bin/sh"
COMMAND="/tmp/tests.sh"

docker run $DOCKER_RUN_OPTS $DOCKER_IMAGE -c $COMMAND
