To run this project a few things are necessary.

Installation
1. Install a DPDK version (only tested on DPDK 19.05, x86 version)(https://core.dpdk.org/download/)
   Guide: (https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html)
2. Install Go (https://golang.org/dl/)
3. Download Prometheus (https://prometheus.io/download/)
4. Download the Prometheus Node Exporter (https://prometheus.io/download/#node_exporter)
5. Go to go/key_manager and call build.sh
6. Go to src and call build.sh

Prometheus Set-up
1. Define Prometheus to scrape data from the node exporter (HTTP 9100) and our metrics exporter (HTTP 8080)
1. Alternatively copy the prometheus.yml file from the prometheus_config folder into the Prometheus installation dir

DPDK Set-up (https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html)
1. Load uio driver: sudo modprobe uio
2. Load igb_driver: sudo modprobe uio_igb
3. If this doesn't work load driver manually
   Go to the DPDK installation directory (e.g. dpdk-19.05/x86_64-native-linuxapp-gcc/)
   and call sudo insmod kmod/igb_uio.ko
4. Call ./usertools/dpdk-devbind.py --status to check the driver status
5. Call ./usertools/dpdk-devbind.py --bind=uio_igb [ETH_NAME] to load a desired eth device

Run
Start Prometheus instance
Start Prometheus node exporter
Run metrics exporter: go run metrics_exporter.go
Start Lightning filter by running sudo run.sh
