package main

import (
	"blockchain/certdemo/certdb"
	"fmt"
	"log"
	"time"
)

func main() {
	for {
		select {
		//改成配置文件的 todo
		case <-time.After(10*time.Second):
			log.Println("timeout: gen cert")
		}
	}
	fmt.Println("test exp")
	//TestExpired()
}

func TestExpired(){
	certdb.DbCert.Deal(certdb.T1)
}
