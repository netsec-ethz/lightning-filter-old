#!/usr/bin/env bash
set -Eeuo pipefail

# See https://yakking.branchable.com/posts/networking-4-namespaces-and-multi-host-routing/


sudo ip netns add fw-111
sudo ip netns add as-111

sudo ip netns add fw-112
sudo ip netns add as-112

sudo ip link add one-112 address 00:76:65:74:68:31 type veth peer name two-112 address 00:76:65:74:68:32
sudo ip link add three-112 address 00:76:65:74:68:33 type veth peer name four-112 address 00:76:65:74:68:34
sudo ip link add infra1-112 address 00:56:45:54:48:31 type veth peer name infra2-112 address 00:56:45:54:48:32
sudo ip link add infra3-112 address 00:56:45:54:48:33 type veth peer name infra4-112 address 00:56:45:54:48:34

sudo ip link add one-111 address 00:76:65:74:78:31 type veth peer name two-111 address 00:76:65:74:78:32
sudo ip link add three-111 address 00:76:65:74:78:33 type veth peer name four-111 address 00:76:65:74:78:34
sudo ip link add infra1-111 address 00:56:45:54:58:31 type veth peer name infra2-111 address 00:56:45:54:58:32
sudo ip link add infra3-111 address 00:56:45:54:58:33 type veth peer name infra4-111 address 00:56:45:54:58:34

sudo ip link set dev two-112 netns fw-112
sudo ip link set dev three-112 netns fw-112
sudo ip link set dev four-112 netns as-112

sudo ip link set dev infra2-112 netns as-112
sudo ip link set dev infra3-112 netns fw-112
sudo ip link set dev infra4-112 netns as-112

sudo ip link set dev two-111 netns fw-111
sudo ip link set dev three-111 netns fw-111
sudo ip link set dev four-111 netns as-111

sudo ip link set dev infra2-111 netns as-111
sudo ip link set dev infra3-111 netns fw-111
sudo ip link set dev infra4-111 netns as-111

sudo ip address add 10.248.3.1/24 dev one-111
sudo ip netns exec fw-111 ip address add 10.248.3.2/24 dev two-111
sudo ip netns exec fw-111 ip address add 10.248.2.2/24 dev three-111
sudo ip netns exec as-111 ip address add 10.248.2.1/24 dev four-111

sudo ip address add 10.248.10.1/24 dev infra1-111
sudo ip netns exec as-111 ip address add 10.248.10.2/24 dev infra2-111
sudo ip netns exec fw-111 ip address add 10.248.7.2/24 dev infra3-111
sudo ip netns exec as-111 ip address add 10.248.7.1/24 dev infra4-111

sudo ip address add 10.248.5.1/24 dev one-112
sudo ip netns exec fw-112 ip address add 10.248.5.2/24 dev two-112
sudo ip netns exec fw-112 ip address add 10.248.4.2/24 dev three-112
sudo ip netns exec as-112 ip address add 10.248.4.1/24 dev four-112

sudo ip address add 10.248.9.1/24 dev infra1-112
sudo ip netns exec as-112 ip address add 10.248.9.2/24 dev infra2-112
sudo ip netns exec fw-112 ip address add 10.248.8.2/24 dev infra3-112
sudo ip netns exec as-112 ip address add 10.248.8.1/24 dev infra4-112

sudo ip link set dev one-112 up
sudo ip netns exec fw-112 ip link set dev two-112 up
sudo ip netns exec fw-112 ip link set dev three-112 up
sudo ip netns exec as-112 ip link set dev four-112 up

sudo ip link set dev infra1-112 up
sudo ip netns exec as-112 ip link set dev infra2-112 up
sudo ip netns exec fw-112 ip link set dev infra3-112 up
sudo ip netns exec as-112 ip link set dev infra4-112 up
sudo ip netns exec as-112 ip link set dev lo up

sudo ip link set dev one-111 up
sudo ip netns exec fw-111 ip link set dev two-111 up
sudo ip netns exec fw-111 ip link set dev three-111 up
sudo ip netns exec as-111 ip link set dev four-111 up

sudo ip link set dev infra1-111 up
sudo ip netns exec as-111 ip link set dev infra2-111 up
sudo ip netns exec fw-111 ip link set dev infra3-111 up
sudo ip netns exec as-111 ip link set dev infra4-111 up
sudo ip netns exec as-111 ip link set dev lo up

sudo ip route add 10.248.4.0/24 dev one-112 via 10.248.5.2
sudo ip route add 10.248.8.0/24 dev infra1-112 via 10.248.9.2

sudo ip route add 10.248.2.0/24 dev one-111 via 10.248.3.2
sudo ip route add 10.248.7.0/24 dev infra1-111 via 10.248.10.2

sudo ip netns exec as-112 ip route add 10.248.5.0/24 dev four-112 via 10.248.4.2
sudo ip netns exec as-112 ip route add default via 10.248.9.1

sudo ip netns exec as-111 ip route add 10.248.3.0/24 dev four-111 via 10.248.2.2
sudo ip netns exec as-111 ip route add default via 10.248.10.1