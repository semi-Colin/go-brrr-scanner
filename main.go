/*
	Possible revise line 19 to change to nested struct
		Want to accept ports as range 1-1024 and also as 1,2,3,4 or just 80
	Review var,const, and init
	Rethink control flow and options

*/

package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"time"
)

type operatingOptions struct {
	threadCount int
	address     string
	waitTime    time.Duration
	portRange   string
}

var (
	synFlag, tcpFlag, ackFlag, udpFlag *bool
	ports                              *string
	options                            operatingOptions
)

const (
	scanDefault  = false
	portsDefault = "1-1024"
	waitDefault  = 1000 //duration in ms
)

func init() {
	flag.BoolVar(synFlag, "s", scanDefault, "SYN (Stealth Scan)")
	flag.BoolVar(tcpFlag, "sT", scanDefault, "TCP Connect Scan")
	flag.BoolVar(ackFlag, "sA", scanDefault, "ACK Scan")
	flag.BoolVar(udpFlag, "sU", scanDefault, "UDP Scan")
	flag.StringVar(ports, "p", portsDefault, "Port range in either 1-1024 or 1,2,3,4 format")
	options.waitTime = time.Millisecond * (*flag.Duration("wait", waitDefault, "Set wait time (ms) between scan attempts, e.g. 1000"))

	if addr := flag.Arg(0); addr != "" {
		options.address = addr
	}

}

// CHANGE THIS
func worker(ports, results chan int) {
	for p := range ports {
		address := fmt.Sprintf("scanme.nmap.org:%d", p)
		conn, err := net.Dial("tcp", address)
		if err != nil {
			results <- 0
			continue
		}
		conn.Close()
		results <- p
	}
}

// CHANGE THIS
func main() {
	// this channel will receive ports to be scanned
	ports := make(chan int, 100)
	// this channel will receive results of scanning
	results := make(chan int)
	// create a slice to store the results so that they can be sorted later.
	var openports []int

	// create a pool of workers
	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}

	// send ports to be scanned
	go func() {
		for i := 1; i <= 1024; i++ {
			ports <- i
		}
	}()

	for i := 0; i < 1024; i++ {
		port := <-results
		if port != 0 {
			openports = append(openports, port)
		}
	}

	// After all the work has been completed, close the channels
	close(ports)
	close(results)
	// sort open port numbers
	sort.Ints(openports)
	for _, port := range openports {
		fmt.Printf("%d open\n", port)
	}
}
