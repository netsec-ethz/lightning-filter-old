package main

import (
	"context"
	"flag"
	"log"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

func runServer(sciondAddr string, localAddr snet.UDPAddr, dataCallback func(data string)) {
	var err error
	ctx := context.Background()

	sdc, err := sciond.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal("Failed to create SCION connector:", err)
	}
	pds := &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(reliable.NewDispatcher("")),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: sciond.RevHandler{Connector: sdc},
		},
	}

	conn, localPort, err := pds.Register(ctx, localAddr.IA, localAddr.Host, addr.SvcNone)
	if err != nil {
		log.Fatal("Failed to register server socket:", err)
	}

	log.Printf("Listening in %v on %v:%d - %v\n", localAddr.IA, localAddr.Host.IP, localPort, addr.SvcNone)

	for {
		var pkt snet.Packet
		var lastHop net.UDPAddr
		err := conn.ReadFrom(&pkt, &lastHop)
		if err != nil {
			log.Printf("Failed to read packet: %v\n", err)
			continue
		}
		pld, ok := pkt.Payload.(snet.UDPPayload)
		if !ok {
			log.Printf("Failed to read packet payload\n")
			continue
		}
		data := string(pld.Payload);
		log.Printf("Received payload: \"%v\"\n", data)
		if dataCallback != nil {
			dataCallback(data)
		}
	}
}

func main() {
	var sciondAddr string
	var localAddr snet.UDPAddr
	flag.StringVar(&sciondAddr, "sciond", "", "SCIOND address")
	flag.Var(&localAddr, "local", "Local address")
	flag.Parse()

	runServer(sciondAddr, localAddr, nil)
}
