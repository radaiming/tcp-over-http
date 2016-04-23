package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/songgao/water"
)

var (
	targetUser     = "nobody"
	tunIP          = "10.45.39.1"
	fakeSrcIP      = "10.45.39.3"
	netmask        = 24
	mtu            = 1500
	listenIP       = tunIP
	byteListenIP   = []byte{0x0a, 0x2d, 0x27, 0x1}
	byteFakeSrcIP  = []byte{0x0a, 0x2d, 0x27, 0x3}
	listenPort     = 39999
	byteListenPort = []byte{0x9c, 0x3f}
	proxyServer    = "127.0.0.1:8123"
	natTable       = make(map[int][][]byte)
)

func check(err error, err_info string) {
	if err != nil {
		fmt.Println(err_info)
		panic(err)
	}
}

func setupTun(name string) {
	err := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%d", tunIP, netmask), "dev", name).Run()
	check(err, "failed to set IP")
	err = exec.Command("ip", "link", "set", name, "up").Run()
	check(err, "failed to bring up device")
	err = exec.Command("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)).Run()
	check(err, "failed to set MTU")
}

func switchUser(iface *water.Interface) {
	// this is not working correctly
	user_info, err := user.Lookup(targetUser)
	check(err, "could not find user "+targetUser)
	target_uid, err := strconv.Atoi(user_info.Uid)
	check(err, "UID is not string ? "+user_info.Uid)
	/*
		_, _, err = syscall.Syscall(
			syscall.SYS_IOCTL,
			uintptr(iface.File().Fd()),
			uintptr(syscall.TUNSETOWNER),
			uintptr(target_uid))
	*/
	check(err, "failed to set TUN owner")
	err = syscall.Setuid(target_uid)
	check(err, "failed to switch UID")
}

func handleConn(conn net.Conn) {
	return
}

func listenServer() {
	addrStr := fmt.Sprintf("%s:%d", listenIP, listenPort)
	listenAddr, err := net.ResolveTCPAddr("tcp", addrStr)
	check(err, "could not parse listen address "+addrStr)
	ln, err := net.ListenTCP("tcp", listenAddr)
	check(err, fmt.Sprintf("could not listen on %s:%d", listenIP, listenPort))
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConn(conn)
	}
}

func manglePacket(packet []byte, srcIP []byte, srcPort []byte, dstIp []byte, dstPort []byte) []byte {
	return []byte{}
}

func handlePacket(iface *water.Interface, packet []byte) {
	if packet[9] != 6 {
		log.Println("non TCP packet received, dropping")
		return
	}
	srcPort := packet[20:21]
	dstPort := packet[22:23]
	srcIP := packet[12:16]
	dstIP := packet[16:20]
	var newPacket []byte
	if bytes.Equal(srcIP, byteListenIP) && bytes.Equal(srcPort, byteListenPort) {
		key := int((dstPort[0] << 8) + dstPort[1])
		addrs, ok := natTable[key]
		if !ok {
			return
		}
		newPacket = manglePacket(packet, addrs[1], addrs[2], addrs[0], dstPort)
	} else {
		key := int((srcPort[0] << 8) + srcPort[1])
		natTable[key] = [][]byte{srcIP, dstIP, dstPort}
		newPacket = manglePacket(packet, byteFakeSrcIP, srcPort, byteListenIP, byteListenPort)
	}
	iface.Write(newPacket)
}

func main() {
	flag.StringVar(&proxyServer, "x", "127.0.0.1:8123", "address:port of proxy server, default to")
	flag.Parse()
	currUser, _ := user.Current()
	if currUser.Uid != "0" {
		fmt.Println("please run this script as root")
		os.Exit(1)
	}

	iface, err := water.NewTUN("")
	check(err, "failed to create TUN device")
	setupTun(iface.Name())
	// switchUser(iface)
	go listenServer()

	buffer := make([]byte, mtu)
	for {
		n, err := iface.Read(buffer)
		check(err, "error reading from TUN")
		go handlePacket(iface, buffer[:n])
	}
}
