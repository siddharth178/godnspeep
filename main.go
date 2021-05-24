package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	bufferSize = int32(4096)
	filter     = "udp and port 53"
)

var debug = false // print size of dns qa map

func deviceExists(name string) bool {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	for _, device := range devices {
		if device.Name == name {
			return true
		}
	}
	return false
}

var mLock = sync.Mutex{}
var m = map[uint16]DNSQA{}

type DNSQA struct {
	dst gopacket.Endpoint
	q   layers.DNS
	a   *layers.DNS
	qt  time.Time
	at  time.Time
}

func printUsage() {
	usage := `Usage: godnspeep <device>

Output columns:
query:     DNS query type (A, CNAME, etc)
name:      Hostname the DNS query is requesting
server IP: IP address of the DNS server the query was made to
elapsed:   How long the DNS response took to arrive (by looking at question packet and answer packet)
response:  Responses from the Answer section of the DNS response (or \"<no response>\" if none was found).
			Multiple responses are separated by commas.`
	fmt.Println(usage)
}

func printHeader() {
	fmt.Println("query, name, server, elapsed, response")
}

func printQA(qa DNSQA) {
	for _, q := range qa.q.Questions {
		response := ""
		if qa.a == nil {
			response = "no/slow response"
		} else {
			if qa.a.ResponseCode != layers.DNSResponseCodeNoErr {
				response = qa.a.ResponseCode.String()
			}
			for _, a := range qa.a.Answers {
				if response == "" {
					response = a.String()
				} else {
					response = fmt.Sprintf("%s,%s", response, a.String())
				}
			}
		}
		fmt.Printf("%s, %s, %s, %v, \"%s\"", q.Type.String(), string(q.Name), qa.dst.String(), qa.at.Sub(qa.qt), response)
		if debug {
			fmt.Printf(", debug:%v\n", len(m))
		} else {
			fmt.Println()
		}
	}
}

func processDNSPacket(dnsLayer gopacket.Layer, dst gopacket.Endpoint) {
	mLock.Lock()
	defer mLock.Unlock()

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		log.Println("warn: non dns packet found")
	}

	if dns.QR {
		// answer
		qa, ok := m[dns.ID]
		if ok {
			qa.a = dns
			qa.at = time.Now()
			printQA(qa)
			delete(m, dns.ID)
		} else {
			log.Println("warn: resp for unknown query id:", dns.ID)
		}
	} else {
		m[dns.ID] = DNSQA{
			dst: dst,
			q:   *dns,
			qt:  time.Now(),
		}

		go func(id uint16) {
			// don't wait for slow responses, cleanup
			time.Sleep(5 * time.Second)

			mLock.Lock()
			defer mLock.Unlock()

			if qa, ok := m[id]; ok {
				qa.at = time.Now()
				printQA(qa)
				delete(m, id)
			}
		}(dns.ID)
	}
}

func main() {
	// debug = true
	log.SetPrefix("[LOG] ")

	flag.Parse()
	if len(flag.Args()) != 1 {
		printUsage()
		os.Exit(1)
	}

	device := flag.Args()[0]
	if !deviceExists(device) {
		log.Fatal("unable to open device ", device)
	}

	handler, err := pcap.OpenLive(device, bufferSize, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	if err := handler.SetBPFFilter(filter); err != nil {
		if err != nil {
			log.Fatal(err)
		}
	}

	printHeader()
	src := gopacket.NewPacketSource(handler, handler.LinkType())
	for p := range src.Packets() {
		dst := p.NetworkLayer().NetworkFlow().Dst()
		if dnsLayer := p.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			processDNSPacket(dnsLayer, dst)
		}
	}
}
