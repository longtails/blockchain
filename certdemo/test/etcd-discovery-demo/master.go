package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
)

type Master struct {
	members map[string]*Member
	KeysAPI client.KeysAPI
}

// Member is a client machine
type Member struct {
	InGroup bool
	IP      string
	Name    string
}

func NewMaster(endpoints []string) *Master {
	cfg := client.Config{
		Endpoints:               endpoints,
		Transport:               client.DefaultTransport,
		HeaderTimeoutPerRequest: time.Second,
	}

	etcdClient, err := client.New(cfg)
	if err != nil {
		log.Fatal("Error: cannot connec to etcd:", err)
	}

	master := &Master{
		members: make(map[string]*Member),
		KeysAPI: client.NewKeysAPI(etcdClient),
	}
	//go master.WatchWorkers()
	return master
}

func (m *Master) AddWorker(info *WorkerInfo) {
	member := &Member{
		InGroup: true,
		IP:      info.IP,
		Name:    info.Name,
	}
	m.members[member.Name] = member
}

func (m *Master) UpdateWorker(info *WorkerInfo) {
	member := m.members[info.Name]
	member.InGroup = true
}

func NodeToWorkerInfo(node *client.Node) *WorkerInfo {
	log.Println(node.Value)
	info := &WorkerInfo{}
	err := json.Unmarshal([]byte(node.Value), info)
	if err != nil {
		log.Print(err)
	}
	return info
}

func (m *Master) WatchWorkers() {
	api := m.KeysAPI
	for true{
		time.Sleep(time.Second*1)
		res,err:=api.Get(context.Background(),"peersbd",nil)
		if res==nil||err!=nil{
			log.Println("watch peers err",err)
			continue
		}
		for _,b:=range res.Node.Nodes{
			fmt.Println(b.Key,b.Value)
		}
	}
	watcher := api.Watcher("peers/", &client.WatcherOptions{
		Recursive: true,
	})
	for {
		fmt.Println("test")
		res, err := watcher.Next(context.Background())
		fmt.Println(res,err)
		if err != nil {
			log.Println("Error watch workers:", err)
			break
		}
		if res.Action == "expire" {
			info := NodeToWorkerInfo(res.PrevNode)
			log.Println("Expire worker ", info.Name)
			member, ok := m.members[info.Name]
			if ok {
				member.InGroup = false
			}
			//删除map中的value
		} else if res.Action == "set" {
			log.Println(res)
			info := NodeToWorkerInfo(res.Node)
			if _, ok := m.members[info.Name]; ok {
				log.Println("Update worker ", info.Name)
				m.UpdateWorker(info)
				//update
			} else {
				log.Println("Add worker ", info.Name)
				m.AddWorker(info)
				//add
			}
		} else if res.Action == "delete" {
			info := NodeToWorkerInfo(res.Node)
			log.Println("Delete worker ", info.Name)
			delete(m.members, info.Name)
		}
	}
}
