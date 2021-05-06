# Proof-of-concept implementation of Lightning Filter together with DRKey on top of today's Internet

## Introduction
As part of the ongoing Lightning Filter project, we have shown that packets can be extremely fast authenticated on a single commodity server core at the network layer. Thanks to the DRKey system [1] this can be achieved without persistent per-sender state at the receiving end host. Based on this property we aim to implement a high-speed packet-filtering system for AWS EC2 deployments that scales to very high rates of traffic. Even though we are starting out with deployments on AWS EC2, the resulting software will also be available for use on other cloud platforms and on premises.

AWS offers a mechanism called Virtual Private Cloud (VPC) ingress routing [2] to redirect incoming traffic through virtual appliances. In a typical VPC setup, Lightning Filter will be placed in a separate subnet from the subnets of the actual end hosts. At the Internet gateway all traffic intended for protected end hosts is routed to one or more Lightning Filter instances (parameterized with address prefix lists consisting of one or more CIDR blocks). This way it can be guaranteed that no unfiltered traffic from the Internet will ever reach the protected subnets. As an implementation restriction of AWS VPC, return traffic from a destination subnet must be routed back through the same (inbound) Lightning Filter appliance to the Internet gateway, i.e., asymmetric routing is not supported. Actual traffic triage is implemented in Lightning Filter for AWS by rewriting source and destination MAC addresses based on the particular filtering decisions. Packets that are allowed to pass through to protected end hosts are directed to the local default gateway whereas other traffic can either be dropped, forwarded to downstream firewall appliances for further inspection, or this traffic can be directly forwarded in a best-effort manner to the protected end host.

For proof-of-concept deployments, not only ingress traffic is routed through Lightning Filter but also all outgoing traffic originating from a protected end host. This allows to add the required filtering information (like timestamps, MACs, and payload hashes) in the form of a custom header on the packet's way out to the Internet. The custom header will then be extracted and stripped out again at the receiving Lightning Filter instance. Packets without the custom Lightning Filter header will be handled without increased availability guarantees on a best-effort basis.

## Deploying Lightning Filter

Reference platform: AWS EC2 instances of type c5n.18xlarge running Amazon Linux 2.

```
cd ~
sudo yum -y update
sudo yum -y groupinstall "Development Tools"
sudo yum -y install numactl-devel libpcap-devel pciutils cmake lshw

cd ~
curl -LO http://fast.dpdk.org/rel/dpdk-19.11.6.tar.xz
echo "2119ea66cf2d1576cc37655901762fc7 dpdk-19.11.6.tar.xz" | md5sum -c
tar xfv dpdk-19.11.6.tar.xz 
cd dpdk-stable-19.11.6/
export RTE_SDK=$(pwd)
make defconfig
make

cd ~
curl -LO https://www.tortall.net/projects/yasm/releases/yasm-1.3.0.tar.gz
echo "3dce6601b495f5b3d45b59f7d2492a340ee7e84b5beca17e48f862502bd5603f  yasm-1.3.0.tar.gz" | sha256sum -c
tar xzfv yasm-1.3.0.tar.gz
cd yasm-1.3.0
./configure
make
sudo make install

cd ~
curl -LO https://golang.org/dl/go1.16.3.linux-amd64.tar.gz
echo "951a3c7c6ce4e56ad883f97d9db74d3d6d80d5fec77455c6ada6c1f7ac4776d2 go1.16.3.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.16.3.linux-amd64.tar.gz
echo >> .bash_profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> .bash_profile
source ~/.bash_profile

cd ~
sudo su
echo "vm.nr_hugepages=4096" >> /etc/sysctl.conf
echo "kernel.randomize_va_space=0" >> /etc/sysctl.conf
reboot
```

## Building Lightning Filter

Uncompress the source archive and change to the Lightning Filter directory, update the section `LF configuration` in `src/scionfwd.c`, update `config/end_hosts.cfg`, and issue

```
cd src
./build.sh
```

## Running Lightning Filter

Attach a second Elastic Network Interface to the Lightning Filter instance and set up VPC ingress routing. Then change to the Lightning Filter directory and issue

```
sudo modprobe uio
sudo insmod ~/dpdk-stable-19.11.6/build/kmod/igb_uio.ko
sudo ifconfig eth1 down
sudo ~/dpdk-stable-19.11.6/usertools/dpdk-devbind.py --bind=igb_uio 0000:00:06.0

sudo src/build/app/scionfwd -c 0x00003ffff00003ffff -- -r 0x1 -x 0x1 -y 0x1 -l -i -K 1 -S 5 -E 750000 -R 10000 -D 2500000
```

## References

[1] Benjamin Rothenberger, Dominik Roos, Markus Legner, and Adrian Perrig. 2020. PISKES: Pragmatic Internet-Scale Key-Establishment System. In Proceedings of the ACM Asia Conference on Computer and Communications Security (ASIACCS). https://doi.org/10.1145/3320269.3384743

[2] Sébastien Stormacq. 2019. VPC Ingress Routing: Simplifying Integration of Third-Party Appliances. https://aws.amazon.com/blogs/aws/new-vpc-ingress-routing-simplifying-integration-of-third-party-appliances
