package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/songgao/water"
)

var (
	target_user  = "nobody"
	tun_ip       = "10.45.39.1"
	fake_src_ip  = "10.45.39.3"
	netmask      = 24
	mtu          = 1500
	listen_ip    = tun_ip
	listen_port  = 39999
	proxy_server = "127.0.0.1:8123"
	nat_table    = make(map[string]string)
)

func check(err error, err_info string) {
	if err != nil {
		fmt.Println(err_info)
		panic(err)
	}
}

func setup_tun(name string) {
	err := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%d", tun_ip, netmask), "dev", name).Run()
	check(err, "failed to set IP")
	err = exec.Command("ip", "link", "set", name, "up").Run()
	check(err, "failed to bring up device")
	err = exec.Command("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)).Run()
	check(err, "failed to set MTU")
}

func switch_user(iface *water.Interface) {
	// this is not working correctly
	user_info, err := user.Lookup(target_user)
	check(err, "could not find user "+target_user)
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

func main() {
	flag.StringVar(&proxy_server, "x", "127.0.0.1:8123", "address:port of proxy server, default to")
	flag.Parse()
	curr_user, _ := user.Current()
	if curr_user.Uid != "0" {
		fmt.Println("please run this script as root")
		os.Exit(1)
	}

	iface, err := water.NewTUN("")
	check(err, "failed to create TUN device")
	setup_tun(iface.Name())
	// switch_user(iface)
	buffer := make([]byte, mtu)
	for {
		_, err := iface.Read(buffer)
		check(err, "error reading from TUN")
		fmt.Println(buffer)
	}
}
