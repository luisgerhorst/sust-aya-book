#!/usr/bin/env bash

set -euo pipefail
set -x

name=aya-book-cgroup-skb-egress

sudo mkdir -p /sys/fs/cgroup/aya-book-cgroup-skb-egress

rm -f target/debug/cgroup-skb-egress
RUST_LOG=info cargo xtask run &
c=$!

sleep 1

sudo bash -c "echo \$$ >> /sys/fs/cgroup/aya-book-cgroup-skb-egress/cgroup.procs && curl google.com"

sudo bash -c "echo \$$ >> /sys/fs/cgroup/aya-book-cgroup-skb-egress/cgroup.procs && curl 1.1.1.1" &
b=$!

sleep 10

kill $b
kill $c
sleep 1

wait
