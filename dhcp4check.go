package main

import (
	"log"
	"net"

	"github.com/mingzhaodotname/dhcp4client"
	"time"
	//dhcp "github.com/krolaw/dhcp4"
	"math/rand"
	//"strconv"
	//"github.com/krolaw/dhcp4/conn"
	"flag"
	"strconv"
	"github.com/mingzhaodotname/dhcp4"
)

func main() {
	//log.Println("this is main")
	cidr := flag.String("cidr", "", "CIDR of an interface, e.g. 192.168.1.3/24")
	mac := flag.String("mac", "", "MAC address")
	flag.Parse()
	log.Println("CIDR: ", *cidr)
	ip, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil {
		log.Fatal("error: ", err)
	}
	log.Println("ip: ", ip, ", mask: ", ipnet.Mask, ", ipnet.ip: ", ipnet.IP)
	ipnet.Mask[0] = 255 ^ ipnet.Mask[0]
	ipnet.Mask[1] = 255 ^ ipnet.Mask[1]
	ipnet.Mask[2] = 255 ^ ipnet.Mask[2]
	ipnet.Mask[3] = 255 ^ ipnet.Mask[3]

	ip[12] = ipnet.Mask[0] | ip[12]
	ip[13] = ipnet.Mask[1] | ip[13]
	ip[14] = ipnet.Mask[2] | ip[14]
	ip[15] = ipnet.Mask[3] | ip[15]
	log.Println("ip: ", ip, ", mask: ", ipnet.Mask, ", ipnet.ip: ", ipnet.IP)

	//ipnet.Mask

	log.Println("MAC: ", *mac)
	//go SendDiscovery()
	ExampleHandler(ip, *mac)

	//go ExampleHandler()
	//SendDiscovery()
}

func ListenAndServe(handler Handler, ip net.IP, mac string) error {
	l, err := net.ListenPacket("udp4", ":68")
	//conn, err := net.ListenUDP("udp4", &c.laddr)
	if err != nil {
		return err
	}
	defer l.Close()
	log.Println("l.LocalAddr(): ", l.LocalAddr())

	// Write DHCP request packet
	log.Println("sending discovery packet")
	dp := dhcp4client.DiscoverPacket(mac);
	//addr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 255), Port: 67}
	addr := &net.UDPAddr{IP: ip, Port: 67}

	if _, e := l.WriteTo(dp, addr); e != nil {
		return e
	}
	log.Println("sent discovery packet successfully.")

	return Serve(l, handler)
}

type Handler interface {
	ServeDHCP(req dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) dhcp4.Packet
}

// ServeConn is the bare minimum connection functions required by Serve()
// It allows you to create custom connections for greater control,
// such as ServeIfConn (see serverif.go), which locks to a given interface.
type ServeConn interface {
	ReadFrom(b []byte) (n int, addr net.Addr, err error)
	WriteTo(b []byte, addr net.Addr) (n int, err error)
}

func Serve(conn ServeConn, handler Handler) error {
	buffer := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		log.Println("DHCP server address: ", addr)
		if err != nil {
			return err
		}
		if n < 240 { // Packet too small to be DHCP
			continue
		}
		req := dhcp4.Packet(buffer[:n])
		if req.HLen() > 16 { // Invalid size
			continue
		}
		options := req.ParseOptions()
		var reqType dhcp4.MessageType
		if t := options[dhcp4.OptionDHCPMessageType]; len(t) != 1 {
			continue
		} else {
			reqType = dhcp4.MessageType(t[0])
			if reqType < dhcp4.Discover || reqType > dhcp4.Inform {
				continue
			}
		}
		if res := handler.ServeDHCP(req, reqType, options); res != nil {
			// If IP not available, broadcast
			ipStr, portStr, err := net.SplitHostPort(addr.String())
			if err != nil {
				return err
			}

			if net.ParseIP(ipStr).Equal(net.IPv4zero) || req.Broadcast() {
				port, _ := strconv.Atoi(portStr)
				addr = &net.UDPAddr{IP: net.IPv4bcast, Port: port}
			}
			if _, e := conn.WriteTo(res, addr); e != nil {
				return e
			}
		}
	}
}


// Example using DHCP with a single network interface device
func ExampleHandler(ip net.IP, mac string) {
	//log.Println("minglog: started ExampleHandler")
	// serverIP := net.IP{10, 0, 2, 15}
	serverIP := net.IP{192, 168, 1, 3}
	handler := &DHCPHandler{
		ip:            serverIP,
		leaseDuration: 2 * time.Hour,
		// start:         net.IP{10, 0, 2, 15},
		start:         net.IP{192, 168, 1, 3},
		leaseRange:    50,
		leases:        make(map[int]lease, 10),
		options: dhcp4.Options{
			dhcp4.OptionSubnetMask:       []byte{255, 255, 255, 0},
			dhcp4.OptionRouter:           []byte(serverIP), // Presuming Server is also your router
			dhcp4.OptionDomainNameServer: []byte(serverIP), // Presuming Server is also your DNS server
		},
	}
	log.Fatal(ListenAndServe(handler, ip, mac))
	// log.Fatal(dhcp4.Serve(dhcp4.NewUDP4BoundListener("eth0",":67"), handler)) // Select interface on multi interface device - just linux for now
	// log.Fatal(dhcp4.Serve(dhcp4.NewUDP4FilterListener("en0",":67"), handler)) // Work around for other OSes
}

type lease struct {
	nic    string    // Client's CHAddr
	expiry time.Time // When the lease expires
}

type DHCPHandler struct {
	ip            net.IP        // Server IP to use
	options       dhcp4.Options  // Options to send to DHCP Clients
	start         net.IP        // Start of IP range to distribute
	leaseRange    int           // Number of IPs to distribute (starting from start)
	leaseDuration time.Duration // Lease period
	leases        map[int]lease // Map to keep track of leases
}

func PrintPacket(p dhcp4.Packet) {
	log.Println("OpCode    :", p.OpCode())
	log.Println("HType     :", p.HType())
	log.Println("HLen      :", p.HLen())
	log.Println("Hops      :", p.Hops())
	log.Println("XId       :", p.XId())
	log.Println("Secs      :", p.Secs())
	log.Println("Flags     :", p.Flags())
	log.Println("CIAddr    :", p.CIAddr())
	log.Println("YIAddr    :", p.YIAddr())
	log.Println("SIAddr    :", p.SIAddr())
	log.Println("GIAddr    :", p.GIAddr())
	log.Println("CHAddr    :", p.CHAddr())
	log.Println("Broadcast :", p.Broadcast())
	//log.Println("Options   :", p.Options())
	//for k, v := range p.Options() {
	//	name := OptionNameDict[k]
	//	log.Println("Option   name:", name, ", value:", v)
	//}
	options := p.ParseOptions()
	for code, v := range options {
		name := OptionNameDict[code]
		log.Println(name, " : ", v)
	}
}

func (h *DHCPHandler) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) (d dhcp4.Packet) {
	switch msgType {

	case dhcp4.Offer:
		log.Println("=== dhcp Offer ===")
		PrintPacket(p)

	case dhcp4.Discover:
		log.Println("=== minglog: dhcp Discover", p, options)
		return nil

		free, nic := -1, p.CHAddr().String()
		for i, v := range h.leases { // Find previous lease
			if v.nic == nic {
				free = i
				goto reply
			}
		}
		if free = h.freeLease(); free == -1 {
			log.Println("=== minglog: dhcp Discover - no free lease")
			return
		}
		reply:
		log.Println("=== minglog: dhcp Discover, free:", free)

		return dhcp4.ReplyPacket(p, dhcp4.Offer, h.ip, dhcp4.IPAdd(h.start, free), h.leaseDuration,
			h.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))

	case dhcp4.Request:
		log.Println("=== minglog: dhcp Request")
		if server, ok := options[dhcp4.OptionServerIdentifier]; ok && !net.IP(server).Equal(h.ip) {
			return nil // Message not for this dhcp server
		}
		reqIP := net.IP(options[dhcp4.OptionRequestedIPAddress])
		if reqIP == nil {
			reqIP = net.IP(p.CIAddr())
		}

		if len(reqIP) == 4 && !reqIP.Equal(net.IPv4zero) {
			if leaseNum := dhcp4.IPRange(h.start, reqIP) - 1; leaseNum >= 0 && leaseNum < h.leaseRange {
				if l, exists := h.leases[leaseNum]; !exists || l.nic == p.CHAddr().String() {
					h.leases[leaseNum] = lease{nic: p.CHAddr().String(), expiry: time.Now().Add(h.leaseDuration)}
					return dhcp4.ReplyPacket(p, dhcp4.ACK, h.ip, reqIP, h.leaseDuration,
						h.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
				}
			}
		}
		return dhcp4.ReplyPacket(p, dhcp4.NAK, h.ip, nil, 0, nil)

	case dhcp4.Release, dhcp4.Decline:
		nic := p.CHAddr().String()
		for i, v := range h.leases {
			if v.nic == nic {
				delete(h.leases, i)
				break
			}
		}
	}
	return nil
}

func (h *DHCPHandler) freeLease() int {
	now := time.Now()
	b := rand.Intn(h.leaseRange) // Try random first
	for _, v := range [][]int{[]int{b, h.leaseRange}, []int{0, b}} {
		for i := v[0]; i < v[1]; i++ {
			if l, ok := h.leases[i]; !ok || l.expiry.Before(now) {
				return i
			}
		}
	}
	return -1
}


func SendDiscovery() {
	log.Println("SendDiscovery")
	time.Sleep(2 * time.Second)
	log.Println("SendDiscovery after sleeping")
	var err error

	//Create a connection to use
	//We need to set the connection ports to 1068 and 1067 so we don't need root access
	c, err := dhcp4client.NewInetSock(
		// 0.0.0.0: can not send: network is unreachable
		//dhcp4client.SetLocalAddr(net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 68}),

		// for test on 192.168.1.2
		//dhcp4client.SetLocalAddr(net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 68}),

		dhcp4client.SetLocalAddr(net.UDPAddr{IP: net.IPv4(192, 168, 1, 3), Port: 68}),
		//dhcp4client.SetLocalAddr(net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 1068}),
		dhcp4client.SetRemoteAddr(net.UDPAddr{IP: net.IPv4bcast, Port: 67}))
	if err != nil {
		log.Println("Client Connection Generation:" + err.Error())
	}
	defer c.Close()

	m, err := net.ParseMAC("08-00-27-00-A8-E8")
	if err != nil {
		log.Printf("MAC Error:%v\n", err)
	}
	exampleClient, err := dhcp4client.New(dhcp4client.HardwareAddr(m), dhcp4client.Connection(c))
	if err != nil {
		log.Printf("Error:%v\n", err)
		return
	}
	defer exampleClient.Close()

	//success, acknowledgementpacket, err := exampleClient.Request()
	success, acknowledgementpacket, err := exampleClient.DiscoverAndOffer()

	log.Println("Success:", success)
	log.Println("Packet:", acknowledgementpacket)
}

var OptionNameDict = map[dhcp4.OptionCode]string {
255 : "End                                              ",
0   : "Pad                                              ",
1   : "OptionSubnetMask                                 ",
2   : "OptionTimeOffset                                 ",
3   : "OptionRouter                                     ",
4   : "OptionTimeServer                                 ",
5   : "OptionNameServer                                 ",
6   : "OptionDomainNameServer                           ",
7   : "OptionLogServer                                  ",
8   : "OptionCookieServer                               ",
9   : "OptionLPRServer                                  ",
10  : "OptionImpressServer                              ",
11  : "OptionResourceLocationServer                     ",
12  : "OptionHostName                                   ",
13  : "OptionBootFileSize                               ",
14  : "OptionMeritDumpFile                              ",
15  : "OptionDomainName                                 ",
16  : "OptionSwapServer                                 ",
17  : "OptionRootPath                                   ",
18  : "OptionExtensionsPath                             ",
//         :                                                              ",
//         :                                                              	// IP Layer Parameters per Host",
19  : "OptionIPForwardingEnableDisable                  ",
20  : "OptionNonLocalSourceRoutingEnableDisable         ",
21  : "OptionPolicyFilter                               ",
22  : "OptionMaximumDatagramReassemblySize              ",
23  : "OptionDefaultIPTimeToLive                        ",
24  : "OptionPathMTUAgingTimeout                        ",
25  : "OptionPathMTUPlateauTable                        ",
//   " :                                                              ",
//   " :                                                              	// IP Layer Parameters per Interface",
26  : "OptionInterfaceMTU                               ",
27  : "OptionAllSubnetsAreLocal                         ",
28  : "OptionBroadcastAddress                           ",
29  : "OptionPerformMaskDiscovery                       ",
30  : "OptionMaskSupplier                               ",
31  : "OptionPerformRouterDiscovery                     ",
32  : "OptionRouterSolicitationAddress                  ",
33  : "OptionStaticRoute                                ",
//     ":                                                              ",
//     ":                                                              	// Link Layer Parameters per Interface",
34  : "OptionTrailerEncapsulation                       ",
35  : "OptionARPCacheTimeout                            ",
36  : "OptionEthernetEncapsulation                      ",
//   " :                                                              ",
//   " :                                                              	// TCP Parameters",
37  : "OptionTCPDefaultTTL                              ",
38  : "OptionTCPKeepaliveInterval                       ",
39  : "OptionTCPKeepaliveGarbage                        ",
//   " :                                                              ",
//   " :                                                              	// Application and Service Parameters",
40  : "OptionNetworkInformationServiceDomain            ",
41  : "OptionNetworkInformationServers                  ",
42  : "OptionNetworkTimeProtocolServers                 ",
43  : "OptionVendorSpecificInformation                  ",
44  : "OptionNetBIOSOverTCPIPNameServer                 ",
45  : "OptionNetBIOSOverTCPIPDatagramDistributionServer ",
46  : "OptionNetBIOSOverTCPIPNodeType                   ",
47  : "OptionNetBIOSOverTCPIPScope                      ",
48  : "OptionXWindowSystemFontServer                    ",
49  : "OptionXWindowSystemDisplayManager                ",
64  : "OptionNetworkInformationServicePlusDomain        ",
65  : "OptionNetworkInformationServicePlusServers       ",
68  : "OptionMobileIPHomeAgent                          ",
69  : "OptionSimpleMailTransportProtocol                ",
70  : "OptionPostOfficeProtocolServer                   ",
71  : "OptionNetworkNewsTransportProtocol               ",
72  : "OptionDefaultWorldWideWebServer                  ",
73  : "OptionDefaultFingerServer                        ",
74  : "OptionDefaultInternetRelayChatServer             ",
75  : "OptionStreetTalkServer                           ",
76  : "OptionStreetTalkDirectoryAssistance              ",
//    "     :                                                              ",
//    "     :                                                              	// DHCP Extensions",
50  : "OptionRequestedIPAddress                         ",
51  : "OptionIPAddressLeaseTime                         ",
52  : "OptionOverload                                   ",
53  : "OptionDHCPMessageType                            ",
54  : "OptionServerIdentifier                           ",
55  : "OptionParameterRequestList                       ",
56  : "OptionMessage                                    ",
57  : "OptionMaximumDHCPMessageSize                     ",
58  : "OptionRenewalTimeValue                           ",
59  : "OptionRebindingTimeValue                         ",
60  : "OptionVendorClassIdentifier                      ",
61  : "OptionClientIdentifier                           ",
//   " :                                                              ",
66  : "OptionTFTPServerName                             ",
67  : "OptionBootFileName                               ",
//   " :                                                              ",
77  : "OptionUserClass                                  ",
//   " :                                                              ",
93  : "OptionClientArchitecture                         ",
//   " :                                                              ",
100 : "OptionTZPOSIXString                              ",
101 : "OptionTZDatabaseString                           ",
//   " :                                                              ",
121 : "OptionClasslessRouteFormat",
}
