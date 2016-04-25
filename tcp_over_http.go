package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"

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
	enableDebug    = false
	natTableLock   sync.RWMutex
)

func logPanicIfErr(msg string, err error) {
	if err != nil {
		log.Panic("%s: %s\n", msg, err)
	}
}

func debug(msg string, err error) {
	if !enableDebug {
		return
	}
	if err != nil {
		log.Printf("%s: %s\n", msg, err)
	} else {
		log.Println(msg)
	}
}

func setupTun(name string) {
	err := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%d", tunIP, netmask), "dev", name).Run()
	logPanicIfErr("failed to set IP", err)
	err = exec.Command("ip", "link", "set", name, "up").Run()
	logPanicIfErr("failed to bring up device", err)
	err = exec.Command("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)).Run()
	logPanicIfErr("failed to set MTU", err)
}

func handleReading(proxyConn *net.TCPConn, listenConn net.Conn) {
	defer proxyConn.Close()
	defer listenConn.Close()
	data := make([]byte, mtu)
	for {
		n, err := proxyConn.Read(data)
		if err != nil {
			if err.Error() != "EOF" {
				debug("error reading from proxy server", err)
			}
			return
		}
		n, err = listenConn.Write(data[:n])
		if err != nil {
			debug("err writing to client", err)
			return
		}
	}
}

func handleConn(listenConn net.Conn) {
	defer listenConn.Close()
	srcPort, err := strconv.Atoi(strings.Split(listenConn.RemoteAddr().String(), ":")[1])
	if err != nil {
		debug("could not get source port of the incoming connection", err)
		return
	}
	natTableLock.RLock()
	_, ok := natTable[srcPort]
	natTableLock.RUnlock()
	if !ok {
		debug(fmt.Sprintf("%d not in nat table", srcPort), nil)
		return
	}
	remoteAddr, _ := net.ResolveTCPAddr("tcp", proxyServer)
	localAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	proxyConn, err := net.DialTCP("tcp", localAddr, remoteAddr)
	if err != nil {
		debug("failed to connect to proxy server", err)
		return
	}
	defer proxyConn.Close()
	natTableLock.RLock()
	x := natTable[srcPort][1]
	y := natTable[srcPort][2]
	natTableLock.RUnlock()
	targetIP := fmt.Sprintf("%d.%d.%d.%d", x[0], x[1], x[2], x[3])
	targetPort := int(y[0])<<8 + int(y[1])
	connStr := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", targetIP, targetPort, targetIP, targetPort)
	proxyConn.Write([]byte(connStr))
	resp := make([]byte, 1024)
	n, err := proxyConn.Read(resp)
	if err != nil {
		debug("error reading from proxy server", err)
		return
	}
	reg := regexp.MustCompile(`HTTP/\d\.\d\s+?(\d+?)\s+?`)
	ret := reg.FindSubmatch(resp[:n])
	returnCode := "unknown"
	if ret != nil {
		returnCode = string(ret[1])
	}
	if returnCode != "200" {
		debug("failed to connect to proxy server: "+returnCode, nil)
		return
	}
	go handleReading(proxyConn, listenConn)
	data := make([]byte, mtu)
	for {
		n, err := listenConn.Read(data)
		if err != nil {
			if err.Error() != "EOF" {
				debug("error reading from client", err)
			}
			return
		}
		_, err = proxyConn.Write(data[:n])
		if err != nil {
			debug("error writing to proxy server", err)
			return
		}
	}
}

func listenServer() {
	addrStr := fmt.Sprintf("%s:%d", listenIP, listenPort)
	listenAddr, err := net.ResolveTCPAddr("tcp", addrStr)
	logPanicIfErr("could not parse listen address", err)
	ln, err := net.ListenTCP("tcp", listenAddr)
	logPanicIfErr("could not listen on given address", err)
	for {
		conn, err := ln.Accept()
		if err != nil {
			debug("error reading client request", err)
			continue
		}
		go handleConn(conn)
	}
}

func manglePacket(packet []byte, srcIP []byte, srcPort []byte, dstIp []byte, dstPort []byte) {
	newAddrChksum, newPortChksum, oldAddrChksum, oldPortChksum := 0, 0, 0, 0
	newAddrChksum += int(srcIP[0])<<8 + int(srcIP[1])
	newAddrChksum += int(srcIP[2])<<8 + int(srcIP[3])
	newAddrChksum += int(dstIp[0])<<8 + int(dstIp[1])
	newAddrChksum += int(dstIp[2])<<8 + int(dstIp[3])
	newPortChksum += int(srcPort[0])<<8 + int(srcPort[1])
	newPortChksum += int(dstPort[0])<<8 + int(dstPort[1])
	for i := 12; i < 20; i += 2 {
		oldAddrChksum += int(packet[i])<<8 + int(packet[i+1])
	}
	for i := 20; i < 24; i += 2 {
		oldPortChksum += int(packet[i])<<8 + int(packet[i+1])
	}
	oldIPChksum := int(packet[10])<<8 + int(packet[11])
	oldTCPChksum := int(packet[36])<<8 + int(packet[37])

	newIPChksum := oldIPChksum - (newAddrChksum - oldAddrChksum)
	for {
		if (newIPChksum >> 16) != 0 {
			newIPChksum = (newIPChksum >> 16) + (newIPChksum & 0xffff)
		} else {
			break
		}
	}

	newTCPChksum := oldTCPChksum - (newAddrChksum + newPortChksum - oldAddrChksum - oldPortChksum)
	for {
		if (newTCPChksum >> 16) != 0 {
			newTCPChksum = (newTCPChksum >> 16) + newTCPChksum&0xffff
		} else {
			break
		}
	}

	binary.BigEndian.PutUint16(packet[10:12], uint16(newIPChksum))
	binary.BigEndian.PutUint16(packet[36:38], uint16(newTCPChksum))
	copy(packet[12:16], srcIP)
	copy(packet[16:20], dstIp)
	copy(packet[20:22], srcPort)
	copy(packet[22:24], dstPort)
}

func handlePacket(iface *water.Interface, packet []byte) {
	if packet[9] != 6 {
		return
	}
	srcPort := make([]byte, 2)
	dstPort := make([]byte, 2)
	srcIP := make([]byte, 4)
	dstIP := make([]byte, 4)
	copy(srcPort, packet[20:22])
	copy(dstPort, packet[22:24])
	copy(srcIP, packet[12:16])
	copy(dstIP, packet[16:20])
	if bytes.Equal(srcIP, byteListenIP) && bytes.Equal(srcPort, byteListenPort) {
		key := int(dstPort[0])<<8 + int(dstPort[1])
		natTableLock.RLock()
		addrs, ok := natTable[key]
		natTableLock.RUnlock()
		if !ok {
			return
		}
		manglePacket(packet, addrs[1], addrs[2], addrs[0], dstPort)
	} else {
		key := int(srcPort[0])<<8 + int(srcPort[1])
		natTableLock.Lock()
		natTable[key] = [][]byte{srcIP, dstIP, dstPort}
		natTableLock.Unlock()
		manglePacket(packet, byteFakeSrcIP, srcPort, byteListenIP, byteListenPort)
	}
	iface.Write(packet)
}

func main() {
	flag.StringVar(&proxyServer, "x", "127.0.0.1:8123", "address:port of proxy server, default to")
	flag.BoolVar(&enableDebug, "debug", false, "enable debug outputing")
	flag.Parse()
	currUser, _ := user.Current()
	if currUser.Uid != "0" {
		fmt.Println("please run this script as root")
		os.Exit(1)
	}

	iface, err := water.NewTUN("")
	logPanicIfErr("failed to create TUN device", err)
	setupTun(iface.Name())
	go listenServer()

	buffer := make([]byte, mtu)
	for {
		n, err := iface.Read(buffer)
		if err != nil {
			log.Panic("%s: %s\n", "error reading from TUN", err)
		}
		handlePacket(iface, buffer[:n])
	}
}
