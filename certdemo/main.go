package main

import (
	"blockchain/certdemo/certdb"
	. "blockchain/certdemo/certifacte"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
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

func init() {
	f, err := os.Open("cert.crt")
	defer f.Close()
	if err != nil {
		log.Println("ca cert does not exist!gen one")
		CA()
	} else {
		log.Println("ca cert exist!")
	}
}
func T1(db *leveldb.DB){
	log.Println("gen new cert")
	iter := db.NewIterator(nil, nil)
	//这里边不能再加锁了
	for iter.Next() {
		pubkey := iter.Key()
		prikey,err:=certdb.DbKey.Get(string(pubkey))
		if err!=nil{
			log.Println(err)
		}
		log.Println(string(prikey))
		clientcert := iter.Value()
		log.Println("cert:",string(clientcert))
		block, _ := pem.Decode([]byte(clientcert))
		cert,err:=x509.ParseCertificate(block.Bytes)
		if err!=nil{
			log.Println(err)
		}
		certstr:=Client(string(prikey),cert.Subject.Country,cert.Subject.Locality,cert.Subject.Province,cert.Subject.OrganizationalUnit,
			cert.Subject.Organization,cert.Subject.StreetAddress,cert.Subject.PostalCode,cert.Subject.CommonName)
		log.Println(certstr)
		err=db.Put(pubkey,[]byte(certstr),nil)
		//err=db.Put(string(prikey),certstr)
		//更新data
		log.Println(err)
	}
	iter.Release()
}
func main() {
	go certdb.DbCert.Deal(func(db	*leveldb.DB){
		for {
			select {
				//改成配置文件的 todo
				case <-time.After(30*time.Minute):
					log.Println("timeout: gen cert")
					//check valid
					certdb.DbCert.Deal(T1)
			}
		}
	})
	web()
}
func web() {
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/fs", fs)
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	//匿名函数注册路由
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		log.Println(err)
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

		//w.Write([]byte(data))
	})
	http.HandleFunc("/register", register)
	http.HandleFunc("/clientKey", clientKey)
	http.HandleFunc("/expired", expired)
	http.HandleFunc("/queryDiffWays", queryCertByDiffWays)
	http.HandleFunc("/test",func(w http.ResponseWriter,r* http.Request){
		fmt.Println(r.RequestURI)
		r.ParseForm()
		for a, b := range r.Form {
			fmt.Println(a,"-",b)
		}
	})
	log.Println("starting service!")

	//log.Fatal输出后，会退出程序,执行os.Exit(1)
	log.Fatal(http.ListenAndServe(":4000", nil))
}


var profile = Profile{"",
	"", "", "", "",
	"", "", "", "",
	"", "", "",""}

func register(w http.ResponseWriter, r *http.Request) {
	//w.Write([]byte("byte byte"))
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
	for a, b := range r.Form {
		if len(b) == 0 {
			//fmt.Println("a:",a,"b:","null")
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
		fmt.Println(pkstr)
		if pkstr[len(pkstr)-1]=='\n'{
			pkstr=pkstr[:len(pkstr)-1]
		}
		//pubkey-clientkey,用于重新生成证书
		//err = certdb.DbKey.Put(string(buf.Bytes()),profile.ClientKey)
		err = certdb.DbKey.Put(pkstr,profile.ClientKey)
		if err!=nil{
			log.Println(err)
		}
		//log.Println(string(buf.Bytes()))
		//pubkey-clientcert
		//err = certdb.DbCert.Put(string(buf.Bytes()),profile.ClientCert)
		err = certdb.DbCert.Put(pkstr,profile.ClientCert)
		if err!=nil{
			log.Println(err)
		}

		//put into bc
		//cmd := exec.Command("./putclientcert.sh",profile.ClientKey,profile.ClientCert)
		//update: key=pubkey
		pubKeyStr:=string(buf.Bytes())

		if pubKeyStr[len(pubKeyStr)-1]=='\n'{
			//log.Println("pubkey laste character is \\n")
			pubKeyStr=pubKeyStr[:len(pubKeyStr)-1]
		}
		cmd := exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+pubKeyStr,
			"--data-urlencode", "car_ca="+profile.ClientCert,
			"-d", "action=set_car_cert",
			"http://114.115.165.101:10000/invoke/set_car_cert")

		log.Println("Running command and waiting for it to finish...")
		/*
		out,err:=cmd.Output()
		 */
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
	tForm := make(map[string]string)
	if r.Form["action"] == nil || len(r.Form["action"]) == 0 {

		if err := tmpl.Execute(w, ClientKey); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		//return
	}
	for a, b := range r.Form {
		if len(b) == 0 {
			//fmt.Println("a:",a,"b:","null")
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
	//本地添加，移除pubkey-cert

	if err := tmpl.Execute(w, ClientKey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func expired(w http.ResponseWriter, r *http.Request) {
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
	tForm := make(map[string]string)
	if r.Form["action"] == nil || len(r.Form["action"]) == 0 {

		if err := tmpl.Execute(w, ExpiredCerted); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		//return
	}
	for a, b := range r.Form {
		if len(b) == 0 {
			//fmt.Println("a:",a,"b:","null")
			tForm[a] = ""
		} else {
			tForm[a] = b[0]
		}
	}

	if tForm["action"]=="ADD"{
		//put into bc todo
		//cmd := exec.Command("./putclientcert.sh",profile.ClientKey,profile.ClientCert)
		ExpiredCerted.PubKey=tForm["PubKey"]
		ExpiredCerted.Status="invalid user"
		if ExpiredCerted.PubKey[len(ExpiredCerted.PubKey)-1]=='\n'{
			ExpiredCerted.PubKey=ExpiredCerted.PubKey[:len(ExpiredCerted.PubKey)-1]
			log.Println("ExpiredCerted.Pubkey last char is \\n")
		}
		ExpiredCerted.PubKey=strings.Replace(ExpiredCerted.PubKey,"\r","",-1)
		//todo  http://114.115.165.101:10000/invoke/set_car_crl
		cmd := exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+ExpiredCerted.PubKey,
			"--data-urlencode", "car_bad_flag="+ExpiredCerted.Status,
			"-d", "action=set_Car_CA",
			"http://114.115.165.101:10000/invoke/set_car_crl")
		log.Printf("Running command and waiting for it to finish...")
		err := cmd.Run()
		if err != nil {
			log.Printf("Command finished with error: %v", err)
			profile.VerifyResp = "write into block error,please retry:" + err.Error()
		} else {
			log.Printf("Command finished successfully")
		}
		//本地添加，移除pubkey-cert
		err=certdb.DbCert.Del(ExpiredCerted.PubKey)
		if err!=nil{
			log.Println(err)
		}
		err=certdb.DbCRL.Put(ExpiredCerted.PubKey,ExpiredCerted.Status)
		if err!=nil{
			log.Println(err)
		}
	} else {
		ExpiredCerted.Status="error command"
	}

	if err := tmpl.Execute(w, ExpiredCerted); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func queryCertByDiffWays(w http.ResponseWriter, r *http.Request) {
	var queryDiff struct {
		BCPubKey string
		BCClientCert string
		NoBCPubKey string
		NoBCClientCert string
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

	//gen cert
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
			//fmt.Println("a:",a,"b:","null")
			tForm[a] = ""
		} else {
			tForm[a] = b[0]
		}
	}

	begin:=time.Now()
	if tForm["action"]=="BCGetCert"{
		log.Println("Get Query by BC")
		queryDiff.BCPubKey=tForm["BCPubKey"]

		//fmt.Println([]byte(queryDiff.BCPubKey))
		if queryDiff.BCPubKey[len(queryDiff.BCPubKey)-1]=='\n'{
			queryDiff.BCPubKey=queryDiff.BCPubKey[:len(queryDiff.BCPubKey)-1]
			log.Println("NoBCPubKey last char is \\n")
		}
		queryDiff.BCPubKey=strings.Replace(queryDiff.BCPubKey,"\r","",-1)



		//pre: query crl
		cmd:= exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+queryDiff.BCPubKey,
			"-d", "action=get_car_crl",
			"http://114.115.165.101:10000/invoke/get_car_crl")
		out,err := cmd.Output()
		if err != nil {
			log.Printf("Command finished with error: %v", err)
			queryDiff.Logs=err.Error()
			profile.VerifyResp = "write into block error,please retry:" + err.Error()
		} else {
			log.Printf("Command finished successfully")
		}
		//parse out
		crlout:=string(out)
		// <textarea name="car_crl_value"></textarea>
		status :=strings.Split(crlout,"<textarea name=\"car_crl_value\">")
		if len(status)<2{
			return
		}
		crlout=status[1]
		status=strings.Split(crlout,"</textarea>")
		//已经在crl中
		if len(status)<2{
			elapsed:=time.Now().Sub(begin)
			queryDiff.Logs="err: no car_crl_value"+"\nin: "+elapsed.String()+"seconds"
		}else if status[0]=="invalid user"{
			elapsed:=time.Now().Sub(begin)
			queryDiff.Logs="this cert is  invalid & in crl"+"\nin: "+elapsed.String()+"seconds"
		}else{
			//query cert
			cmd = exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+queryDiff.BCPubKey,
				"-d", "action=get_car_cert",
				"http://114.115.165.101:10000/invoke/get_car_cert")
			out,err = cmd.Output()
			if err != nil {
				log.Printf("Command finished with error: %v", err)
				queryDiff.Logs=err.Error()
				profile.VerifyResp = "write into block error,please retry:" + err.Error()
			} else {
				log.Printf("Command finished successfully")
			}
			//parse out
			queryDiff.BCClientCert=string(out)
			certs:=strings.Split(queryDiff.BCClientCert,"<textarea name=\"car_cert_value\">")
			if len(certs)<2{
				return
			}
			queryDiff.BCClientCert=certs[1]
			certs=strings.Split(queryDiff.BCClientCert,"</textarea>")
			queryDiff.BCClientCert=certs[0]
			//calculate time
			elapsed:=time.Now().Sub(begin)
			queryDiff.Logs="GetCert in: "+elapsed.String()+"seconds"

		}
	}else if tForm["action"]=="NoBCGetCert"{
		log.Println("Get Query by NoBC")
		time.Sleep(time.Duration(rand.Intn(100)+100)*time.Millisecond)

		queryDiff.NoBCPubKey=tForm["NoBCPubKey"]
		if len(queryDiff.NoBCPubKey)==0{
			log.Println("input is null")
			_,err =w.Write([]byte("input is null"))
			return
		}
		if queryDiff.NoBCPubKey[len(queryDiff.NoBCPubKey)-1]=='\n'{
			queryDiff.NoBCPubKey=queryDiff.NoBCPubKey[:len(queryDiff.NoBCPubKey)-1]
			log.Println("NoBCPubKey last char is \\n")
		}
		queryDiff.NoBCPubKey=strings.Replace(queryDiff.NoBCPubKey,"\r","",-1)
		//用于检查控制符
		//log.Println([]byte(queryDiff.NoBCPubKey))

		//本地不用先访问crl,因为添加进crl的时候，删除了cert
		queryDiff.NoBCClientCert,err=certdb.DbCert.Get(queryDiff.NoBCPubKey)
		if err!=nil{
			queryDiff.Logs=err.Error()
		}else{
			elapsed:=time.Now().Sub(begin)
			queryDiff.Logs="GetCert in: "+elapsed.String()+"seconds"
		}
	}
	log.Println(queryDiff.Logs)
	if err := tmpl.Execute(w, queryDiff); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err)
	}
}