package goscan

import (
	"time"
)

type portData struct {
	list   []int
	min    int
	max    int
	absMax int
	total  int
}

type ScanParams struct {
	address  string
	waitTime time.Duration
}

func synScan() {

}

func tcpScan() {

}

func ackScan() {

}
func udpScan() {

}
