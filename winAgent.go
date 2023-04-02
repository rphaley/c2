package main

import (
	"fmt"
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

	// bind the socket to the localhost address and port 1234
	addr := syscall.SockaddrInet4{Port: 1234, Addr: [4]byte{172, 20, 242, 200}}
	err = syscall.Bind(sock, &addr)
	if err != nil {
		fmt.Println("Error binding socket:", err.Error())
		return
	}
	fmt.Println("Server listening on localhost:1234")

	// receive a message from the client
	buffer := make([]byte, 1024)
	n, _, err := syscall.Recvfrom(sock, buffer, 0)
	if err != nil {
		fmt.Println("Error receiving message:", err.Error())
		return
	}

	// print the message
	fmt.Println("Received message:", string(buffer[:n]))

	// send a response back to the client
	message := []byte("Hello, client!")
	err = syscall.Sendto(sock, message, 0, &addr)
	if err != nil {
		fmt.Println("Error sending response:", err.Error())
		return
	}
}
