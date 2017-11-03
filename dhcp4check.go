package main

import (
	"log"
	"net"
	"os"

	"github.com/mingzhaodotname/dhcp4client"
	"time"
	//dhcp "github.com/krolaw/dhcp4"
	"math/rand"
	//"strconv"
	//"github.com/krolaw/dhcp4/conn"
	"flag"
	"strconv"
	"github.com/mingzhaodotname/dhcp4"
	"strings"
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
		if (strings.Contains(name, "BootFileName") || strings.Contains(name, "TFTPServerName") || strings.Contains(name, "DomainName ")) {
			// log.Println(code, name, " : ", string(v[:]))
			log.Printf("Option %2d, %s: %v", code, name, string(v[:]))
		} else if strings.Contains(name, "DHCPMessageType") {
			message_type := ""
			if v[0] == 1 {
				message_type = "Discovery"
			} else if v[0] == 2 {
				message_type = "Offer"
			} else {
				message_type = "other"
			}
			//log.Println(code, name, " : ", message_type, v)
			log.Printf("Option %2d, %s: %s, %v", code, name, message_type, v)
		} else {
//			log.Println(code, name, " : ", v)
			log.Printf("Option %2d, %s: %v", code, name, v)
		}
	}
}

func (h *DHCPHandler) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) (d dhcp4.Packet) {
	switch msgType {

	case dhcp4.Offer:
		log.Println("=== dhcp Offer ===")
		PrintPacket(p)
		os.Exit(0)

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
1   : "SubnetMask                                 ",
2   : "TimeOffset                                 ",
3   : "Router                                     ",
4   : "TimeServer                                 ",
5   : "NameServer                                 ",
6   : "DomainNameServer                           ",
7   : "LogServer                                  ",
8   : "CookieServer                               ",
9   : "LPRServer                                  ",
10  : "ImpressServer                              ",
11  : "ResourceLocationServer                     ",
12  : "HostName                                   ",
13  : "BootFileSize                               ",
14  : "MeritDumpFile                              ",
15  : "DomainName                                 ",
16  : "SwapServer                                 ",
17  : "RootPath                                   ",
18  : "ExtensionsPath                             ",
//         :                                                              ",
//         :                                                              	// IP Layer Parameters per Host",
19  : "IPForwardingEnableDisable                  ",
20  : "NonLocalSourceRoutingEnableDisable         ",
21  : "PolicyFilter                               ",
22  : "MaximumDatagramReassemblySize              ",
23  : "DefaultIPTimeToLive                        ",
24  : "PathMTUAgingTimeout                        ",
25  : "PathMTUPlateauTable                        ",
//   " :                                                              ",
//   " :                                                              	// IP Layer Parameters per Interface",
26  : "InterfaceMTU                               ",
27  : "AllSubnetsAreLocal                         ",
28  : "BroadcastAddress                           ",
29  : "PerformMaskDiscovery                       ",
30  : "MaskSupplier                               ",
31  : "PerformRouterDiscovery                     ",
32  : "RouterSolicitationAddress                  ",
33  : "StaticRoute                                ",
//     ":                                                              ",
//     ":                                                              	// Link Layer Parameters per Interface",
34  : "TrailerEncapsulation                       ",
35  : "ARPCacheTimeout                            ",
36  : "EthernetEncapsulation                      ",
//   " :                                                              ",
//   " :                                                              	// TCP Parameters",
37  : "TCPDefaultTTL                              ",
38  : "TCPKeepaliveInterval                       ",
39  : "TCPKeepaliveGarbage                        ",
//   " :                                                              ",
//   " :                                                              	// Application and Service Parameters",
40  : "NetworkInformationServiceDomain            ",
41  : "NetworkInformationServers                  ",
42  : "NetworkTimeProtocolServers                 ",
43  : "VendorSpecificInformation                  ",
44  : "NetBIOSOverTCPIPNameServer                 ",
45  : "NetBIOSOverTCPIPDatagramDistributionServer ",
46  : "NetBIOSOverTCPIPNodeType                   ",
47  : "NetBIOSOverTCPIPScope                      ",
48  : "XWindowSystemFontServer                    ",
49  : "XWindowSystemDisplayManager                ",
64  : "NetworkInformationServicePlusDomain        ",
65  : "NetworkInformationServicePlusServers       ",
68  : "MobileIPHomeAgent                          ",
69  : "SimpleMailTransportProtocol                ",
70  : "PostOfficeProtocolServer                   ",
71  : "NetworkNewsTransportProtocol               ",
72  : "DefaultWorldWideWebServer                  ",
73  : "DefaultFingerServer                        ",
74  : "DefaultInternetRelayChatServer             ",
75  : "StreetTalkServer                           ",
76  : "StreetTalkDirectoryAssistance              ",
//    "     :                                                              ",
//    "     :                                                              	// DHCP Extensions",
50  : "RequestedIPAddress                         ",
51  : "IPAddressLeaseTime                         ",
52  : "Overload                                   ",
53  : "DHCPMessageType                            ",
54  : "ServerIdentifier                           ",
55  : "ParameterRequestList                       ",
56  : "Message                                    ",
57  : "MaximumDHCPMessageSize                     ",
58  : "RenewalTimeValue                           ",
59  : "RebindingTimeValue                         ",
60  : "VendorClassIdentifier                      ",
61  : "ClientIdentifier                           ",
//   " :                                                              ",
66  : "TFTPServerName                             ",
67  : "BootFileName                               ",
//   " :                                                              ",
77  : "UserClass                                  ",
//   " :                                                              ",
93  : "ClientArchitecture                         ",
//   " :                                                              ",
100 : "TZPOSIXString                              ",
101 : "TZDatabaseString                           ",
//   " :                                                              ",
121 : "ClasslessRouteFormat",
}
