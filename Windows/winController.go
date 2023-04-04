package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

const protocolICMP = 1

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ip-address> <message>\n", os.Args[0])
		os.Exit(1)
	}

	// create a raw socket for ICMP protocol
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protocolICMP)
	if err != nil {
		fmt.Println("Error creating socket:", err.Error())
		return
	}
	defer syscall.Close(sock)

	// resolve the IP address and build a socket address
	addr := net.ParseIP(os.Args[1])
	if addr == nil {
		fmt.Fprintf(os.Stderr, "Invalid IP address: %s\n", os.Args[1])
		os.Exit(1)
	}
	sockaddr := syscall.SockaddrInet4{Port: 1234, Addr: [4]byte{addr[0], addr[1], addr[2], addr[3]}}

	// build a message to send
	message := []byte(os.Args[2])

	// send the message using the raw socket
	err = syscall.Sendto(sock, message, 0, &sockaddr)
	if err != nil {
		fmt.Println("Error sending message:", err.Error())
		return
	}

	// receive a response from the server
	buffer := make([]byte, 1024)
	n, _, err := syscall.Recvfrom(sock, buffer, 0)
	if err != nil {
		fmt.Println("Error receiving response:", err.Error())
		return
	}

	// print the response
	fmt.Println("Received response:", string(buffer[:n]))
}