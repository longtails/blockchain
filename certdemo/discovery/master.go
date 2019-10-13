package discovery

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
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
	info := &WorkerInfo{}
	err := json.Unmarshal([]byte(node.Value), info)
	if err != nil {
		log.Print(err)
	}
	fmt.Println(node)
	return info
}

func NodeToKV(node *client.Node) *WorkerInfo {
	if node!=nil{
		return &WorkerInfo{node.Key,node.Value}
	}else{
		return nil
	}
}

func (m *Master) WatchWorkers() {
	api := m.KeysAPI
	watcher := api.Watcher("peers/", &client.WatcherOptions{
		Recursive: true,
	})
	for {

		res, err := watcher.Next(context.Background())
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

func (m *Master) WatchPeers(key string,mp* sync.Map){
	api := m.KeysAPI
	//初始化
	res,err:=api.Get(context.Background(),key,nil)
	if res==nil||err!=nil{
		log.Println("watch peers err",err)
	}else{
		for _,val:=range res.Node.Nodes{
			mp.Store(val.Key,val.Value)
			log.Print(val.Value," ",)
		}
		log.Println()
	}
	watcher := api.Watcher(key, &client.WatcherOptions{
		Recursive: true,
	})

	//test
	go func(){
		for false{
			fmt.Println("peers")
			mp.Range(
				func(a,b interface{})bool{
				fmt.Println(a,b)
				return true
			})
			time.Sleep(time.Second*3)
		}
	}()
	//监听
	for {
		res, err := watcher.Next(context.Background())
		if err != nil {
			log.Println("Error watch peers:", err)
			break
		}
		if res.Action == "expire" {
			//expire /peers/47.112.33.105 47.112.33.105:11000 {Key: /peers/47.112.33.105, CreatedIndex: 4525, ModifiedIndex: 4538, TTL: 0}
			//fmt.Println("expire",res.PrevNode.Key,res.PrevNode.Value,res.PrevNode)
			mp.Delete(res.PrevNode.Key)
			//info := NodeToWorkerInfo(res.PrevNode)
			info := NodeToKV(res.PrevNode)
			if info==nil{
				log.Println("no key and value")
				continue
			}
			log.Println("Expired peer:",info.Name,info.IP)
			member, ok := m.members[info.Name]
			if ok {
				member.InGroup = false
			}
			mp.Delete(info.Name+"@"+info.IP)
			//删除map中的value
		} else if res.Action == "set" {
			//{Key: /peers/0.0.0.0, CreatedIndex: 4540, ModifiedIndex: 4540, TTL: 60} /peers/0.0.0.0 0.0.0.0:11000
			//fmt.Println(res.Node,res.Node.Key,res.Node.Value)
			//info := NodeToWorkerInfo(res.Node)
			info := NodeToKV(res.Node)
			if info==nil{
				log.Println("no key and value")
			}
			if _, ok := m.members[info.Name]; ok {
				//update
				m.UpdateWorker(info)
			} else {
				//add
				log.Println("Discover peer:", info.Name,info.IP)
				m.AddWorker(info)
			}
			mp.Store(info.Name+"@"+info.IP,info.IP)
			//mp.Store(info.Name+"@"+info.IP,info.IP)
		} else if res.Action == "delete" {
			//fmt.Println(res.Node,res.Node.Key,res.Node.Value)
			//info := NodeToWorkerInfo(res.Node)
			info := NodeToKV(res.Node)
			if info==nil{
				log.Println("no key and value")
				continue
			}
			log.Println("Delete peer:", info.Name,info.IP)
			//删除掉成员
			delete(m.members, info.Name)
			mp.Delete(info.Name+"@"+info.IP)
		}else{
			//其他信息
			log.Println("other info",res.Action,res)
		}
	}
}