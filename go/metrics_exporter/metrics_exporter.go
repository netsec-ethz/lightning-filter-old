package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)
import (
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

/* IPC SOCKET TO LISTEN TO */
const SockAddr = "/tmp/echo.sock"

/* Prometheus export port 8080 */

var (
	addr = flag.String("listen-address", ":8080", "The address to listen on for HTTP requests.")
)

var KeyRolloverCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "key_rollovers",
		Help: "number of rollovers for a specific AS",
	},
	[]string{"AS"},
)

var KeyASInfo = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "scion_as_key_info",
		Help: "Info about AS keys",
	},
	[]string{"AS", "epoch_begin", "epoch_end"},
)

var KeyInfo = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "scion_key_info",
		Help: "Info about key manager",
	},
	[]string{"key_grace_period"},
)

var BloomFilterInfo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "bloom_filter_info",
		Help: "Info on the bloom filter configuration",
	},
	[]string{"nb_filters", "nb_elements", "false_positive_rate", "rotation_interval"},
)

var PortMaskInfo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "portmask_info",
		Help: "Info about portmasks",
	},
	[]string{"nb_active_ports", "nb_rx_ports", "nb_tx_bypass_ports", "nb_tx_firewall_ports", "rx_portmask", "tx_bypass_portmask", "tx_firewall_portmask"},
)

var ScionFilterInfo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "scion_filter_info",
		Help: "Info on the scion_filter configuration",
	},
	[]string{"key_rotation_interval", "stats_interval", "packet_receive_limit"},
)

var CoreInfo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "scion_core_info",
		Help: "Info on the scion_filter configuration",
	},
	[]string{"nb_core_total", "nb_slave_cores", "nb_stats_cores", "nb_key_manager_cores", "nb_cmd_cores"},
)

var PortInfo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "port_info",
		Help: "Info on the scion_filter configuration",
	},
	[]string{"port_id", "socket_id", "driver_name", "if_index",
		"min_mtu", "max_mtu", "dev_flags", "min_rx_bufsize",
		"max_rx_pktlen", "max_rx_queues", "max_tx_queues",
		"max_mac_addrs", "max_vfs", "max_vmdq_pools",
		"rx_offload_capa", "tx_offload_capa",
		"rx_queue_offload_capa", "tx_queue_offload_capa", "reta_size",
		"hash_key_size", "flow_type_rss_offloads", "speed_capa", "dev_capa"},
)

var PortRxPacketCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "port_rx_packets",
		Help: "number of packets received per port",
	},
	[]string{"port_id"},
)

var PortTxPacketCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "port_tx_packets",
		Help: "number of packets sent per port",
	},
	[]string{"port_id"},
)

var PortRxByteCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "port_rx_bytes",
		Help: "number of bytes received per port",
	},
	[]string{"port_id"},
)

var PortTxByteCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "port_tx_pbytes",
		Help: "number of bytes send per port",
	},
	[]string{"port_id"},
)

var PortHWDroppedPacketCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "port_hw_dropped_packets",
		Help: "number of packets dropped by hardware",
	},
	[]string{"port_id"},
)

var PortErrorRxByteCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "port_error_rx_bytes",
		Help: "number of errornous bytes received per port",
	},
	[]string{"port_id"},
)

var PortErrorRxPacketCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "port_error_rx_packets",
		Help: "number of errornous packets received per port",
	},
	[]string{"port_id"},
)

var PortRxMbufAllocFailCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "port_mbuf_alloc_fails",
		Help: "number of mbuf allocation errrors per port",
	},
	[]string{"port_id"},
)

var CoreRxPacketCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "rx_packets_c",
		Help: "number of packets received per core",
	},
	[]string{"core_id"},
)

var CoreTxBypassPacketCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "tx_bypass_packets_c",
		Help: "number of bypass packets send per core",
	},
	[]string{"core_id"},
)

var CoreTxFirewallPacketCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "tx_firewall_c",
		Help: "number of firewall packets send per core",
	},
	[]string{"core_id"},
)

var CoreKeyMismatchCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "key_missmatches_c",
		Help: "number key missmatches per core",
	},
	[]string{"core_id"},
)

var CoreSecXFailCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "secX_fails_c",
		Help: "number of secX per core",
	},
	[]string{"core_id"},
)

var CoreBloomFilterHitCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bloom_filter_hits_c",
		Help: "number of blomm filter hits per core",
	},
	[]string{"core_id"},
)

var CoreBloomFilterMissCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "bloom_filter_misses_c",
		Help: "number of misses per core",
	},
	[]string{"core_id"},
)

func convert(param string) float64 {
	result, _ := strconv.ParseFloat(param, 64)
	return result
}

func echoServer(c net.Conn) {
	log.Printf("Client connected [%s]", c.RemoteAddr().Network())
	for {
		buf := make([]byte, 1024)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]
		messages := strings.Split(string(data), "fin\n")
		for _, token := range messages {
			line := strings.Split(string(token), ";")
			if len(line) <= 1 {
				continue
			}

			if string(line[0]) == "core_stats" && len(line) == 10 {
				parseCoreStats(line)
			} else if string(line[0]) == "port_stats" && len(line) == 11 {
				parsePortStats(line)
			} else if string(line[0]) == "set_up_sys_stats" && len(line) == 16 {
				parseSetUpSysStats(line)
			} else if string(line[0]) == "set_up_port_stats" && len(line) == 27 {
				parseSetUpPortStats(line)
			} else if string(line[0]) == "key_stats" && len(line) == 8 {
				parseKeyStats(line)
			} else {
				fmt.Printf("ERROR:: unknown message received: %v\n", line)
			}
		}
	}
}

func parseKeyStats(keyStat []string) {
	fmt.Println("rollover count: ", keyStat[2])
	KeyRolloverCount.WithLabelValues(keyStat[1]).Set(convert(keyStat[2]))
	labels := prometheus.Labels{"AS": keyStat[1], "epoch_begin": keyStat[3],
		"epoch_end": keyStat[4]}
	KeyASInfo.With(labels).Set(1)
	KeyInfo.WithLabelValues(keyStat[6]).Set(convert(keyStat[5]))

}

func parseCoreStats(coreStat []string) {
	fmt.Println("core stat: ", coreStat)

	CoreRxPacketCount.WithLabelValues(coreStat[1]).Set(convert(coreStat[2]))
	CoreTxBypassPacketCount.WithLabelValues(coreStat[1]).Set(convert(coreStat[3]))
	CoreTxFirewallPacketCount.WithLabelValues(coreStat[1]).Set(convert(coreStat[4]))
	CoreKeyMismatchCount.WithLabelValues(coreStat[1]).Set(convert(coreStat[5]))
	CoreSecXFailCount.WithLabelValues(coreStat[1]).Set(convert(coreStat[6]))
	CoreBloomFilterHitCount.WithLabelValues(coreStat[1]).Set(convert(coreStat[7]))
	CoreBloomFilterMissCount.WithLabelValues(coreStat[1]).Set(convert(coreStat[8]))

}

func parsePortStats(portStat []string) {
	fmt.Println("port stat: ", portStat)

	PortRxPacketCount.WithLabelValues(portStat[1]).Set(convert(portStat[2]))
	PortTxPacketCount.WithLabelValues(portStat[1]).Set(convert(portStat[3]))
	PortRxByteCount.WithLabelValues(portStat[1]).Set(convert(portStat[4]))
	PortTxByteCount.WithLabelValues(portStat[1]).Set(convert(portStat[5]))
	PortHWDroppedPacketCount.WithLabelValues(portStat[1]).Set(convert(portStat[6]))
	PortErrorRxByteCount.WithLabelValues(portStat[1]).Set(convert(portStat[7]))
	PortErrorRxPacketCount.WithLabelValues(portStat[1]).Set(convert(portStat[8]))
	PortRxMbufAllocFailCount.WithLabelValues(portStat[1]).Set(convert(portStat[9]))
}

func parseSetUpSysStats(iSysStat []string) {
	fmt.Println("init sys stat: ", iSysStat)
	labels := prometheus.Labels{"nb_filters": iSysStat[2], "nb_elements": iSysStat[3],
		"false_positive_rate": iSysStat[4], "rotation_interval": iSysStat[5]}
	BloomFilterInfo.With(labels).Add(1)

	labels = prometheus.Labels{"nb_active_ports": iSysStat[7], "nb_rx_ports": iSysStat[8],
		"nb_tx_bypass_ports": iSysStat[10], "nb_tx_firewall_ports": iSysStat[11],
		"rx_portmask": "MISSING", "tx_bypass_portmask": "MISSING", "tx_firewall_portmask": "MISSING"}
	PortMaskInfo.With(labels).Add(1)

	labels = prometheus.Labels{"nb_core_total": iSysStat[12], "nb_slave_cores": iSysStat[13],
		"nb_stats_cores": "1", "nb_key_manager_cores": "1",
		"nb_cmd_cores": "1"}
	CoreInfo.With(labels).Add(1)

	labels = prometheus.Labels{"key_rotation_interval": iSysStat[6], "stats_interval": iSysStat[1],
		"packet_receive_limit": iSysStat[14]}
	ScionFilterInfo.With(labels).Add(1)
}

func parseSetUpPortStats(ips []string) {
	fmt.Println("init port stat: ", ips)
	labels := prometheus.Labels{"port_id": ips[1], "socket_id": ips[2],
		"driver_name": ips[3], "if_index": ips[4], "min_mtu": ips[5],
		"max_mtu": ips[6], "dev_flags": ips[7], "min_rx_bufsize": ips[8],
		"max_rx_pktlen": ips[9], "max_rx_queues": ips[10], "max_tx_queues": ips[11],
		"max_mac_addrs": ips[12], "max_vfs": ips[13],
		"max_vmdq_pools": ips[14], "rx_offload_capa": ips[15], "tx_offload_capa": ips[16],
		"rx_queue_offload_capa": ips[17], "tx_queue_offload_capa": ips[18], "reta_size": ips[19],
		"hash_key_size": ips[20], "flow_type_rss_offloads": ips[21], "speed_capa": ips[22], "dev_capa": ips[23]}
	PortInfo.With(labels).Add(1)

}

func echorrServer(c net.Conn) {
	log.Printf("Client connected [%s]", c.RemoteAddr().Network())
	io.Copy(c, c)
	c.Close()
}

func init_prometheus() {
	fmt.Printf("starting promehteus handle\n")

	fmt.Printf("register values\n")
	prometheus.MustRegister(CoreRxPacketCount)
	prometheus.MustRegister(CoreTxBypassPacketCount)
	prometheus.MustRegister(CoreTxFirewallPacketCount)
	prometheus.MustRegister(CoreKeyMismatchCount)
	prometheus.MustRegister(CoreSecXFailCount)
	prometheus.MustRegister(CoreBloomFilterHitCount)
	prometheus.MustRegister(CoreBloomFilterMissCount)

	prometheus.MustRegister(PortRxPacketCount)
	prometheus.MustRegister(PortTxPacketCount)
	prometheus.MustRegister(PortRxByteCount)
	prometheus.MustRegister(PortTxByteCount)
	prometheus.MustRegister(PortHWDroppedPacketCount)
	prometheus.MustRegister(PortErrorRxByteCount)
	prometheus.MustRegister(PortErrorRxPacketCount)
	prometheus.MustRegister(PortRxMbufAllocFailCount)

	prometheus.MustRegister(BloomFilterInfo)
	prometheus.MustRegister(PortMaskInfo)
	prometheus.MustRegister(CoreInfo)
	prometheus.MustRegister(ScionFilterInfo)
	prometheus.MustRegister(PortInfo)

	prometheus.MustRegister(KeyRolloverCount)
	prometheus.MustRegister(KeyASInfo)
	prometheus.MustRegister(KeyInfo)

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(*addr, nil))

}

func ipc_main() {
	if err := os.RemoveAll(SockAddr); err != nil {
		log.Fatal(err)
	}

	l, err := net.Listen("unix", SockAddr)
	fmt.Printf("Started listening\n")
	if err != nil {
		log.Fatal("listen error:", err)
	}
	defer l.Close()

	for {
		// Accept new connections, dispatching them to echoServer
		// in a goroutine.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}

		go echoServer(conn)
	}
}
func main() {

	fmt.Printf("Starting service\n")
	go init_prometheus()
	ipc_main()

}
