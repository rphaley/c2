package main

import (
	"fmt"
	"net"
	"syscall"
)

const protocolICMP = 1

func main() {
	// create a raw socket for ICMP protocol
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protocolICMP)
	if err != nil {
		fmt.Println("Error creating socket:", err.Error())
		return
	}
	defer syscall.Close(sock)

	// build a socket address to listen on all interfaces and port 1234
	sockaddr := syscall.SockaddrInet4{Port: 1234}

	// bind the socket to the address
	err = syscall.Bind(sock, &sockaddr)
	if err != nil {
		fmt.Println("Error binding socket:", err.Error())
		return
	}

	// receive a response from the server
	buffer := make([]byte, 1024)
	n, _, err := syscall.Recvfrom(sock, buffer, 0)
	if err != nil {
		fmt.Println("Error receiving response:", err.Error())

		// try to receive the response using the net package
		conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			fmt.Println("Error creating connection:", err.Error())
			return
		}
		defer conn.Close()

		// receive the response using the net package
		_, _, err = conn.ReadFrom(buffer)
		if err != nil {
			fmt.Println("Error receiving response:", err.Error())
			return
		}

	}
	// print the message
	fmt.Println("Received message:", string(buffer[:n]))


}
