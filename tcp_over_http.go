package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/songgao/water"
)

var (
	proxyServer = "127.0.0.1:7070"
	deviceName  = ""
	enableDebug = false
)

// Server TUN Server
type Server struct {
	targetUser      string
	tunIP           string
	fakeSrcIP       string
	netmask         uint32
	mtu             int
	listenIP        string
	listenPort      uint16
	byteListenIP    []byte
	byteFakeSrcIP   []byte
	byteListenPort  []byte
	proxyServerAddr string
	remoteAddr      *net.TCPAddr
	natTable        sync.Map
	enableDebug     bool
}

func logPanicIfErr(msg string, err error) {
	if err != nil {
		log.Panicf("%s: %s\n", msg, err)
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

func (s *Server) setupTun(name string) {
	err := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%d", s.tunIP, s.netmask), "dev", name).Run()
	logPanicIfErr("failed to set IP", err)
	err = exec.Command("ip", "link", "set", name, "up").Run()
	logPanicIfErr("failed to bring up device", err)
	err = exec.Command("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(s.mtu)).Run()
	logPanicIfErr("failed to set MTU", err)
}

func (s *Server) handleReading(proxyConn *net.TCPConn, listenConn net.Conn) {
	data := make([]byte, s.mtu)
	for {
		n, err := proxyConn.Read(data)
		if err != nil {
			if err.Error() != "EOF" {
				debug("error reading from proxy server", err)
			}
			return
		}
		_, err = listenConn.Write(data[:n])
		if err != nil {
			debug("err writing to client", err)
			return
		}
	}
}

func (s *Server) handleConn(listenConn net.Conn) {
	defer listenConn.Close()
	// avoid concurrent rw
	srcPort := strings.Split(listenConn.RemoteAddr().String(), ":")[1]
	v, ok := s.natTable.Load(srcPort)
	if !ok {
		debug(fmt.Sprintf("%s not in nat table", srcPort), nil)
		return
	}
	addrs := v.([][]byte)
	x := addrs[1]
	y := addrs[2]
	targetIP := fmt.Sprintf("%d.%d.%d.%d", x[0], x[1], x[2], x[3])
	targetPort := int(y[0])<<8 + int(y[1])
	proxyConn, err := net.DialTCP("tcp", nil, s.remoteAddr)
	if err != nil {
		debug("failed to connect to proxy server", err)
		return
	}
	defer proxyConn.Close()

	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       nil,
		Header:     make(http.Header),
		Host:       fmt.Sprintf("%s:%d", targetIP, targetPort),
	}
	err = req.WriteProxy(proxyConn)
	if err != nil {
		debug("error writing proxy server", err)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), nil)
	if err != nil {
		debug("error reading proxy server", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		debug(fmt.Sprintf("failed to connect to proxy server: %d", resp.StatusCode), nil)
		return
	}
	go s.handleReading(proxyConn, listenConn)
	data := make([]byte, s.mtu)
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

func (s *Server) listenServer() {
	addrStr := fmt.Sprintf("%s:%d", s.listenIP, s.listenPort)
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
		go s.handleConn(conn)
	}
}

func manglePacket(packet []byte, srcIP []byte, srcPort []byte, dstIP []byte, dstPort []byte) {
	newAddrChksum, newPortChksum, oldAddrChksum, oldPortChksum := 0, 0, 0, 0
	newAddrChksum += int(srcIP[0])<<8 + int(srcIP[1])
	newAddrChksum += int(srcIP[2])<<8 + int(srcIP[3])
	newAddrChksum += int(dstIP[0])<<8 + int(dstIP[1])
	newAddrChksum += int(dstIP[2])<<8 + int(dstIP[3])
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
	copy(packet[16:20], dstIP)
	copy(packet[20:22], srcPort)
	copy(packet[22:24], dstPort)
}

func (s *Server) handlePacket(iface *water.Interface, packet []byte) {
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
	if bytes.Equal(srcIP, s.byteListenIP) && bytes.Equal(srcPort, s.byteListenPort) {
		key := strconv.Itoa(int(dstPort[0])<<8 + int(dstPort[1]))
		v, ok := s.natTable.Load(key)
		if !ok {
			return
		}
		addrs := v.([][]byte)
		manglePacket(packet, addrs[1], addrs[2], addrs[0], dstPort)
	} else {
		key := strconv.Itoa(int(srcPort[0])<<8 + int(srcPort[1]))
		s.natTable.Store(key, [][]byte{srcIP, dstIP, dstPort})
		manglePacket(packet, s.byteFakeSrcIP, srcPort, s.byteListenIP, s.byteListenPort)
	}
	iface.Write(packet)
}

func main() {
	flag.StringVar(&proxyServer, "x", "127.0.0.1:7070", "address:port of proxy server, default to")
	flag.StringVar(&deviceName, "n", "", "tun device name")
	flag.BoolVar(&enableDebug, "debug", false, "enable debug outputing")
	flag.Parse()

	remoteAddr, err := net.ResolveTCPAddr("tcp", proxyServer)
	if err != nil {
		logPanicIfErr("unable resolve tcp addr", err)
	}

	s := Server{
		targetUser:      "nobody",
		tunIP:           "10.45.39.1",
		fakeSrcIP:       "10.45.39.3",
		netmask:         24,
		mtu:             1500,
		listenIP:        "10.45.39.1",
		listenPort:      39999,
		byteListenIP:    []byte{0x0a, 0x2d, 0x27, 0x1},
		byteFakeSrcIP:   []byte{0x0a, 0x2d, 0x27, 0x3},
		byteListenPort:  []byte{0x9c, 0x3f},
		natTable:        sync.Map{},
		enableDebug:     enableDebug,
		remoteAddr:      remoteAddr,
		proxyServerAddr: proxyServer,
	}

	iface, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: deviceName}})
	logPanicIfErr("failed to create TUN device", err)
	s.setupTun(iface.Name())
	go s.listenServer()

	fmt.Println("tcp_over_http started")
	buffer := make([]byte, s.mtu)
	for {
		n, err := iface.Read(buffer)
		if err != nil {
			log.Panicf("%s: %s\n", "error reading from TUN", err)
		}
		s.handlePacket(iface, buffer[:n])
	}
}
