package main

import (
	"flag"
	"fmt"
)
func main(){
	
	var role = flag.String("role", "", "master | worker")
	flag.Parse()
	endpoints := []string{"http://106.15.46.11:32791"}
	if *role == "master" {
		master := NewMaster(endpoints)
		master.WatchWorkers()
	} else if *role == "worker" {
		worker := NewWorker("peer0", "106.15.46.11", endpoints)
		worker.HeartBeat()
	} else {
		fmt.Println("example -h for usage")
	}
}
