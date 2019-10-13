package main

import (
	"blockchain/certdemo/certdb"
	. "blockchain/certdemo/certifacte"
	"blockchain/certdemo/discovery"
	"blockchain/certdemo/push"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/spf13/viper"
	"github.com/syndtr/goleveldb/leveldb"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)


var ExpiredCerted struct{
	PubKey string
	Status string
	URL string
}
var ClientKey struct{
	PriKey string
	PubKey string
	URL string
}

type Profile struct {
	ClientKey                                         string
	Country, Locality, Province, OrgUnit, Org, Street string
	PostalCode, CommonName                            string
	ClientCert, RootCert, VerifyResp                  string
	URL string
}

//配置信息：服务启动端口，区块链服务地址
var Config =make(map[string][]string)
var Peers sync.Map
func init() {
	//生成根证书
	f, err := os.Open("cert.crt")
	defer f.Close()
	if err != nil {
		log.Println("ca cert does not exist!gen one")
		CA()
	} else {
		log.Println("ca cert exist!")
	}

	//读取配置文件config.yaml
	viper.SetConfigName("config")     //设置配置文件的名字
	viper.AddConfigPath(".")           //添加配置文件所在的路径
	viper.SetConfigType("yaml")       //设置配置文件类型，可选
	err = viper.ReadInConfig()
	if err != nil {
		log.Printf("config file error: %s\n", err)
		os.Exit(1)
	}
	Config["server"]=[]string{fmt.Sprintf("%s",viper.Get("server"))}
	Config["etcdServers"]=viper.GetStringSlice("etcdServers")
	//bsServers配置成etcd的地址
	go func(){
		endpoints:=Config["etcdServers"]
		master := discovery.NewMaster(endpoints)
		span:=1
		for i:=0;i<1000;i++{//正常这里只会启动一次
		log.Println("watch peers")
			master.WatchPeers("peers/",&Peers)
			time.Sleep(time.Duration(span*2)*time.Second)
			span*=2
		}
	}()

	Config["expired"]=[]string{viper.GetString("expired")}
	for k,v:=range Config{
		log.Println(k,v)
	}
	if len(Config["server"])==0||len(Config["etcdServers"])==0{
		log.Fatal("must config params server and bcServers in config.yaml")
	}
}

func main() {
	//模拟过期，定时重新生成证书
	go certdb.DbCert.Deal(func(db	*leveldb.DB){
		log.Println("in dbcert.deal timer:")
		duration:=1800//默认1800*minutes
		if v,ok:=Config["expired"];ok&&len(v)>0{
			t,err:=strconv.Atoi(v[0])
			if err==nil{
				duration=t
			}
		}
		log.Println("duration time(minutes):"+strconv.Itoa(duration))
		for {
			select {
				case <-time.After(time.Duration(duration)*time.Minute):
					log.Println("timeout: gen cert")
					certdb.DbCert.Deal(updateCert)
			}
		}
	})
	//启动消息推送服务,websocket
	go push.PushServer()
	//并发查询服务
	go queryCronJob()
	web() //路由
}
//回调函数：重新生成证书
func updateCert(db *leveldb.DB){
	log.Println("gen new cert")

	servers:=make([]string,0)
	Peers.Range(func(key,value interface{})bool{
		servers=append(servers,value.(string))
		return true
	})
	if len(servers)==0{
		log.Println("updateCert error: can`t find peers")
		return
	}
	peerIP:=servers[rand.Int()%len(servers)]


	iter := db.NewIterator(nil, nil)
	log.Println("Running command and waiting for it to finish...")
	//这里边不能再加锁了
	for iter.Next() {
		pubkey := iter.Key()
		prikey,err:=certdb.DbKey.Get(string(pubkey))
		if err!=nil{
			log.Println(err)
		}
		log.Println(string(prikey))
		clientcert := iter.Value()
		block, _ := pem.Decode([]byte(clientcert))
		cert,err:=x509.ParseCertificate(block.Bytes)
		if err!=nil{
			log.Println(err)
		}
		//根据证书的原有信息，生成新的证书
		certstr:=Client(string(prikey),cert.Subject.Country,cert.Subject.Locality,cert.Subject.Province,cert.Subject.OrganizationalUnit,
			cert.Subject.Organization,cert.Subject.StreetAddress,cert.Subject.PostalCode,cert.Subject.CommonName)
		err=db.Put(pubkey,[]byte(certstr),nil)
		//更新data,到区块链上
		cmd := exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+string(pubkey),
			"--data-urlencode", "car_ca="+certstr,
			"-d", "action=set_car_cert",
			"http://"+peerIP+"/cert-issue-system-sdk/set_car_cert")
		//将新生成的证书提交到链上
		err = cmd.Run()
		if err != nil {
			log.Printf("update cert error: %v", err)
		}
	}
	log.Println("update cert finished!")
	iter.Release()
}
//web服务
func web() {
	fs := http.FileServer(http.Dir("static"))
	//加载静态文件
	http.Handle("/fs", fs)
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	//根页显示
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		fp := path.Join("templates", "page1.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type Profile struct {
			URL  string
			Show string
			QueryDiff string
		}
		profile := Profile{r.Host, r.Host,r.Host}
		if err := tmpl.Execute(w, profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	//生成证书，并注册到链上
	http.HandleFunc("/register", register)
	//生成演示用的key
	http.HandleFunc("/clientKey", clientKey)
	//过期的证书，pubkey添加到crl中
	http.HandleFunc("/expired", expired)
	//查询cert by pubkey
	http.HandleFunc("/queryDiffWays", queryCert)

	log.Println("starting service!")

	if len(Config["server"])>0{
		log.Fatal(http.ListenAndServe(Config["server"][0], nil))
	}else{
		log.Fatal(http.ListenAndServe(":4000", nil))
	}
}


var profile = Profile{"",
	"", "", "", "",
	"", "", "", "",
	"", "", "",""}

func register(w http.ResponseWriter, r *http.Request) {
	log.Println("in register:")


	servers:=make([]string,0)
	Peers.Range(func(key,value interface{})bool{
		servers=append(servers,value.(string))
		return true
	})
	if len(servers)==0{
		http.Error(w,"can`t find peers",http.StatusInternalServerError)
		return
	}
	peerIP:=servers[rand.Int()%len(servers)]


	profile.URL=r.Host
	fp := path.Join("templates", "page2.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//gen cert
	r.ParseForm()
	tForm := make(map[string]string)
	if r.Form["action"] == nil || len(r.Form["action"]) == 0 {
		if err := tmpl.Execute(w, profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	//解析url参数
	for a, b := range r.Form {
		if len(b) == 0 {
			tForm[a] = ""
		} else {
			tForm[a] = b[0]
		}
	}
	//update root cert
	crt, err := os.Open("cert.crt")
	defer crt.Close()
	buf := make([]byte, 2048)
	n, err := crt.Read(buf)
	profile.RootCert = string(buf[:n])

	if tForm["action"] == "GEN" {
		log.Println("GEN:")
		profile.ClientKey = tForm["clientkey"]
		profile.Country = tForm["country"]
		profile.Locality = tForm["locality"]
		profile.Province = tForm["province"]
		profile.Org = tForm["org"]
		profile.OrgUnit = tForm["orgunit"]
		profile.Street = tForm["street"]
		profile.PostalCode = tForm["postalocde"]
		profile.CommonName = tForm["commonname"]
		profile.ClientCert = tForm["clientcert"]
		//profile.RootCert=tForm["rootcert"]
		profile.VerifyResp = tForm["verifyresp"]

		profile.ClientCert = Client(profile.ClientKey,
			[]string{profile.Country}, []string{profile.Locality}, []string{profile.Province},
			[]string{profile.OrgUnit}, []string{profile.Org}, []string{profile.Street},
			[]string{profile.PostalCode}, profile.CommonName)

		//put into db
		block, _ := pem.Decode([]byte(profile.ClientKey))
		priKey, err := x509.ParseECPrivateKey(block.Bytes)
		pubKey := priKey.Public()
		key,err:=x509.MarshalPKIXPublicKey(pubKey)
		buf:= new(bytes.Buffer)
		err=pem.Encode(buf, &pem.Block{Type: "EC Public KEY", Bytes: key})
		if err!=nil{
			log.Println(err)
		}
		pkstr:=string(buf.Bytes())

		if pkstr[len(pkstr)-1]=='\n'{
			pkstr=pkstr[:len(pkstr)-1]
		}
		//pubkey-clientkey(私钥),用于重新生成证书
		err = certdb.DbKey.Put(pkstr,profile.ClientKey)
		if err!=nil{
			log.Println(err)
		}
		//pubkey-clientcert
		err = certdb.DbCert.Put(pkstr,profile.ClientCert)
		if err!=nil{
			log.Println(err)
		}

		//put into bc
		pubKeyStr:=string(buf.Bytes())
		if pubKeyStr[len(pubKeyStr)-1]=='\n'{
			pubKeyStr=pubKeyStr[:len(pubKeyStr)-1]
		}
		cmd := exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+pubKeyStr,
			"--data-urlencode", "car_ca="+profile.ClientCert,
			"-d", "action=set_car_cert",
			"http://"+peerIP+"/cert-issue-system-sdk/set_car_cert")

		log.Println("Running command and waiting for it to finish...")
		err = cmd.Run()
		if err != nil {
			log.Printf("Command finished with error: %v", err)
			profile.VerifyResp = "write into block error,please retry:" + err.Error()
		}

	} else if tForm["action"] == "verify" {
		log.Println("verify")
		if ok, err := Verify(profile.RootCert, profile.ClientCert); !ok {
			profile.VerifyResp = err.Error()
		} else {
			profile.VerifyResp = "ok"
		}
	}

	if err := tmpl.Execute(w, profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}


type ecdsaGen struct {
	curve elliptic.Curve
}
func (e *ecdsaGen) KeyGen() (key *ecdsa.PrivateKey, err error) {
	privKey, err := ecdsa.GenerateKey(e.curve, crand.Reader)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}
func clientKey(w http.ResponseWriter, r *http.Request) {
	log.Println("in client key:")
	ClientKey.URL=r.Host
	fp := path.Join("templates", "page5.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//gen cert
	err=r.ParseForm()
	if err!=nil{
		log.Println(err)
	}
	//解析url参数
	tForm := make(map[string]string)
	if r.Form["action"] == nil || len(r.Form["action"]) == 0 {
		if err := tmpl.Execute(w, ClientKey); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	for a, b := range r.Form {
		if len(b) == 0 {
			tForm[a] = ""
		} else {
			tForm[a] = b[0]
		}
	}
	//启动程序默认产生一个key
	if len(ClientKey.PriKey)==0{
		//私钥
		e2 := &ecdsaGen{curve: elliptic.P256()}
		clientPriKey,_ := e2.KeyGen()
		clientPriKeyEncode, _ := x509.MarshalECPrivateKey(clientPriKey)
		bufKey := new(bytes.Buffer)
		err =pem.Encode(bufKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: clientPriKeyEncode})
		ClientKey.PriKey=string(bufKey.Bytes())
		//公钥
		clientPubKey := clientPriKey.Public()
		clientPubKeyEncode, _ := x509.MarshalPKIXPublicKey(clientPubKey)
		bufKey.Reset()
		err =pem.Encode(bufKey, &pem.Block{Type: "EC Public KEY", Bytes: clientPubKeyEncode})
		ClientKey.PubKey=string(bufKey.Bytes())
	}
	//点击Gen可重新产生一个key
	if tForm["action"]=="ReGenClientKey"{
		//私钥
		e2 := &ecdsaGen{curve: elliptic.P256()}
		clientPriKey,_ := e2.KeyGen()
		clientPriKeyEncode, _ := x509.MarshalECPrivateKey(clientPriKey)
		bufKey := new(bytes.Buffer)
		err =pem.Encode(bufKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: clientPriKeyEncode})
		ClientKey.PriKey=string(bufKey.Bytes())
		//公钥
		clientPubKey := clientPriKey.Public()
		clientPubKeyEncode, _ := x509.MarshalPKIXPublicKey(clientPubKey)
		bufKey.Reset()
		err =pem.Encode(bufKey, &pem.Block{Type: "EC Public KEY", Bytes: clientPubKeyEncode})
		ClientKey.PubKey=string(bufKey.Bytes())
	}
	tForm["PubKey"]=ClientKey.PubKey
	tForm["PriKey"]=ClientKey.PriKey

	//返回静态页面
	if err := tmpl.Execute(w, ClientKey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func expired(w http.ResponseWriter, r *http.Request) {
	//load
	servers:=make([]string,0)
	Peers.Range(func(key,value interface{})bool{
		servers=append(servers,value.(string))
		return true
	})
	if len(servers)==0{
		http.Error(w,"can`t find peers",http.StatusInternalServerError)
		return
	}
	peerIP:=servers[rand.Int()%len(servers)]

	log.Println("in expired:")
	ExpiredCerted.URL=r.Host
	fp := path.Join("templates", "page3.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//gen cert
	err=r.ParseForm()
	if err!=nil{
		log.Println(err)
	}
	//解析url参数
	tForm := make(map[string]string)
	if r.Form["action"] == nil || len(r.Form["action"]) == 0 {
		if err := tmpl.Execute(w, ExpiredCerted); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	for a, b := range r.Form {
		if len(b) == 0 {
			tForm[a] = ""
		} else {
			tForm[a] = b[0]
		}
	}
	if tForm["action"]=="ADD"{
		ExpiredCerted.PubKey=tForm["PubKey"]
		ExpiredCerted.Status="expired user"
		if ExpiredCerted.PubKey[len(ExpiredCerted.PubKey)-1]=='\n'{
			ExpiredCerted.PubKey=ExpiredCerted.PubKey[:len(ExpiredCerted.PubKey)-1]
			log.Println("ExpiredCerted.Pubkey last char is \\n")
		}
		ExpiredCerted.PubKey=strings.Replace(ExpiredCerted.PubKey,"\r","",-1)
		//将cert添加到crl中:pubkey into crl
		cmd := exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+ExpiredCerted.PubKey,
			"--data-urlencode", "car_bad_flag="+ExpiredCerted.Status,
			"-d", "action=set_Car_CA",
			"http://"+peerIP+"/cert-issue-system-sdk/set_car_crl")
		log.Printf("Running command and waiting for it to finish...")
		err := cmd.Run()
		if err != nil {
			log.Printf("Command finished with error: %v", err)
			profile.VerifyResp = "write into block error,please retry:" + err.Error()
		} else {
			log.Printf("Command finished successfully")
		}
		//本地certdb，移除pubkey-cert
		err=certdb.DbCert.Del(ExpiredCerted.PubKey)
		if err!=nil{
			log.Println(err)
		}
		//将cert加入到crldb中
		err=certdb.DbCRL.Put(ExpiredCerted.PubKey,ExpiredCerted.Status)
		if err!=nil{
			ExpiredCerted.Status="add dbcrl error"
			log.Println(err)
		}
	} else {
		//ExpiredCerted.Status="error command"
	}

	if err := tmpl.Execute(w, ExpiredCerted); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

var conQueryBC =make(chan []string)
func queryCronHelper(params []string){
	//params[0] pubkey,params[1] type
	if len(params)<2{
		log.Println("input error")
	}
	topic:=params[2]
	//本地缓存记录
	/*
	status,err:=certdb.DbCRL.Get(params[0])
	if err==nil&&len(status)!=0{
		push.Push(params[0]+" : "+status)
		return
	}
	*/
	//并发查询
	go func(key string,n int){
		if topic=="bc"{
			Logs:=queryByBc(key,n)
			push.Push(Logs)
		}
		push.Push(topic+":"+" is done From "+params[3]+" ")
	}(params[0],0)
}
func queryCronJob(){
	log.Println("启动常驻并发任务")
	for{
		select{
			case bc:=<-conQueryBC:
				time.Sleep(3*time.Second)
				push.Push("init jobs by bc From "+bc[3]+" ")
				//query and timing
				begin:=time.Now()
				queryCronHelper(bc)
				elapsed:=time.Now().Sub(begin)
				time.Sleep(2*time.Second)
				push.Push("jobs done by bc From "+bc[3]+" ")
				logs:=" spend "+elapsed.String()
				push.PushWithEnd(bc[2]+":"+logs+" From "+bc[3]+" ","\n")
			//case

		}
	}
}
//n:表示选择哪个节点，目前暂定最多3个
func queryByBc(BCPubKey string,n int )string{
	log.Println("in queryByBC:")

	//load peers
	servers:=make([]string,0)
	Peers.Range(func(key,value interface{})bool{
		servers=append(servers,value.(string))
		return true
	})
	if len(servers)==0{
		return "can`t find peers"
	}
	peerIP:=servers[rand.Int()%len(servers)]

	if BCPubKey[len(BCPubKey)-1]=='\n'{
		BCPubKey=BCPubKey[:len(BCPubKey)-1]
		log.Println("NoBCPubKey last char is \\n")
	}
	BCPubKey=strings.Replace(BCPubKey,"\r","",-1)
	//查询该证书是否在crl列表中
	cmd:= exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+BCPubKey,
		"-d", "action=get_car_crl",
		"http://"+peerIP+"/cert-issue-system-sdk/get_car_crl")
	out,err := cmd.Output()
	Logs:=""
	if err != nil {
		log.Printf("Command finished with error: %v", err)
		Logs=err.Error()
		profile.VerifyResp = "write into block error,please retry:" + err.Error()
	} else {
		log.Printf("Command finished successfully")
	}
	//解析出证书状态
	crlout:=string(out)
	// <textarea name="car_crl_value"></textarea>
	status :=strings.Split(crlout,"<textarea name=\"car_crl_value\">")
	if len(status)<2{
		return Logs
	}
	crlout=status[1]
	status=strings.Split(crlout,"</textarea>")
	log.Println("status of this key: "+status[0])
	if len(status)<2{
		Logs="err: no car_crl_value"
	}else if status[0]=="expired user"{
		//已经在crl中
		Logs="this cert is  expired & in crl"
	}else{
		//不在crl中，query cert
		cmd = exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+BCPubKey,
			"-d", "action=get_car_cert",
			"http://"+peerIP+"/cert-issue-system-sdk/get_car_cert")
		out,err = cmd.Output()
		if err != nil {
			log.Printf("Command finished with error: %v", err)
			Logs=err.Error()
			profile.VerifyResp = "write into block error,please retry:" + err.Error()
		} else {
			log.Printf("Command finished successfully")
		}
		//parse out
		BCClientCert:=string(out)
		certs:=strings.Split(BCClientCert,"<textarea name=\"car_cert_value\">")
		if len(certs)<2{
			return Logs
		}
		//得到证书
		BCClientCert=certs[1]
		certs=strings.Split(BCClientCert,"</textarea>")
		BCClientCert=certs[0]
		//显示日志
		push.PushCert(BCClientCert)
		Logs="GetCert"
	}
	return Logs
}


func queryCert(w http.ResponseWriter, r *http.Request) {
	var queryDiff struct {//暂时不能删，因为go template用的这个结构数据
		BCPubKey string
		BCClientCert string
		//NoBCPubKey string
		//NoBCClientCert string
		Logs string
		URL string
	}
	queryDiff.URL=r.Host

	fp := path.Join("templates", "page4.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}


	r.ParseForm()
	tForm := make(map[string]string)
	if r.Form["action"] == nil || len(r.Form["action"]) == 0 {
		if err := tmpl.Execute(w, queryDiff); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	for a, b := range r.Form {
		if len(b) == 0 {
			tForm[a] = ""
		} else {
			tForm[a] = b[0]
		}
	}
	queryDiff.BCPubKey=tForm["BCPubKey"]
	//queryDiff.NoBCPubKey=tForm["NoBCPubKey"]
	queryDiff.BCClientCert=tForm["BCClientCert"]
	//queryDiff.NoBCClientCert=tForm["NoBCClientCert"]
	queryDiff.Logs=tForm["Logs"]
	if tForm["action"]=="BCGetCert"{
		log.Println("Get Query by BC")
		queryDiff.BCPubKey=tForm["BCPubKey"]
		//将查询消息发送给并发任务
		conQueryBC<-[]string{queryDiff.BCPubKey,queryDiff.BCClientCert,"bc",r.RemoteAddr}
	}
	if err := tmpl.Execute(w, queryDiff); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err)
	}
}