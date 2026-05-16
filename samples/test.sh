#!/usr/bin/env sh
set -u

echo "hello from sandbox"
id
uname -a
ls -la /sample /tmp
touch /tmp/sandbox-write-test
