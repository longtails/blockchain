package test

import (
	"blockchain/certdemo/push"
	"fmt"
	"time"
)

func main(){
	fmt.Println("pushing msg now")
	go func(){
		for {
			push.Push("now send by you")
			time.Sleep(time.Second*2)
		}
	}()
}
