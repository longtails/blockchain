package main

import (
	"blockchain/certdemo/certdb"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)
func main() {
	//启动消息推送服务
	web()
}
type NoBC struct{
	Status string
	Key string
	Cert string
}
func web() {
	http.HandleFunc("/queryByNoBC", queryByNoBc)
	log.Println("starting service!")
	//log.Fatal输出后，会退出程序,执行os.Exit(1)
	log.Fatal(http.ListenAndServe(":5000", nil))
}
func queryByNoBc(w http.ResponseWriter,r*http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Println(err)
		return
	}
	tForm := make(map[string]string)
	for a, b := range r.Form {
		if len(b) == 0 {
			//fmt.Println("a:",a,"b:","null")
			tForm[a] = ""
		} else {
			tForm[a] = b[0]
		}
	}
	fmt.Println(tForm)
	fmt.Println(r.RequestURI)
	var resp NoBC
	resp.Key=tForm["pubKey"]
	resp.Key=strings.Replace(resp.Key,"\r","",-1)
	//用于检查控制符
	//log.Println([]byte(queryDiff.NoBCPubKey))

	//本地不用先访问crl,因为添加进crl的时候，删除了cert
	resp.Cert,err=certdb.DbCert.Get(resp.Key)
	if err!=nil{
		resp.Status=err.Error()
	}else{
		//log.Println(NoBCClientCert)
		resp.Status="ok"
	}
	//resp.Status="ok"
	data,err:=json.Marshal(resp)
	fmt.Println(string(data))
	if err!=nil{
		log.Println(err)
	}else{
		_,err=w.Write(data)
		if err!=nil{
			log.Println(err)
		}
	}
}
func queryByNoBcTest(w http.ResponseWriter,r*http.Request) {
	var resp NoBC

	var NoBCPubKey string=`-----BEGIN EC Public KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+wmZKMQrSnzF0XjCycAjaDo5Ecog
JfuLVvjmpBKhqLd0FQ4RGUjdtV5DzcYN6R74gp6nTlFgTxhIyq0c9vvlKw==
-----END EC Public KEY-----`
	log.Println("Get Query by NoBC")
	if NoBCPubKey[len(NoBCPubKey)-1]=='\n'{
		NoBCPubKey=NoBCPubKey[:len(NoBCPubKey)-1]
		log.Println("NoBCPubKey last char is \\n")
	}

/*
-----BEGIN EC Public KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+wmZKMQrSnzF0XjCycAjaDo5Ecog
JfuLVvjmpBKhqLd0FQ4RGUjdtV5DzcYN6R74gp6nTlFgTxhIyq0c9vvlKw==
-----END EC Public KEY-----
-----BEGIN CERTIFICATE-----
MIICijCCAi+gAwIBAgIQcE55k4i5XjO3yUdMw0/B1DAKBggqhkjOPQQDAjCBsjEL
MAkGA1UEBhMCQ04xEDAOBgNVBAgTB0JlaWppbmcxFTATBgNVBAcTDHpob25nZ3Vh
bmN1bjEsMA0GA1UECRMGc3RyZWV0MA4GA1UECRMHYWRkcmVzczALBgNVBAkTBGRl
bW8xDzANBgNVBBETBjMxMDAwMDERMA8GA1UEChMIcGFyYWRpc2UxDTALBgNVBAsT
BHRlY3QxGTAXBgNVBAMTEGRlbW8uZXhhbXBsZS5jb20wHhcNMTkwMjE5MTMzNjU4
WhcNMjAwMjE5MTMzNjU4WjBNMQkwBwYDVQQGEwAxCTAHBgNVBAgTADEJMAcGA1UE
BxMAMQkwBwYDVQQJEwAxCTAHBgNVBBETADEJMAcGA1UEChMAMQkwBwYDVQQLEwAw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT7CZkoxCtKfMXReMLJwCNoOjkRyiAl
+4tW+OakEqGot3QVDhEZSN21XkPNxg3pHviCnqdOUWBPGEjKrRz2++Uro4GKMIGH
MA4GA1UdDwEB/wQEAwIBpjAPBgNVHSUECDAGBgRVHSUAMAwGA1UdEwEB/wQCMAAw
KQYDVR0OBCIEILE3wP6Vw19ySz3ZknkX6JORK+MahWv96QNBtcVJFoqVMCsGA1Ud
IwQkMCKAII5LW8yeTR0EB7ScK6R/7EM8LWOWhNgQpyO/6pGWkKPbMAoGCCqGSM49
BAMCA0kAMEYCIQDIi4s54+QTTXZ0BaQT7t+V8EazLW/WNgJ1z6U8iHlYEQIhAJe2
rQ9rst0D6//VZ9cbWw5niUbz55eCbxMkOawT4KqL
-----END CERTIFICATE-----
	*/
	NoBCPubKey=strings.Replace(NoBCPubKey,"\r","",-1)
	fmt.Println(NoBCPubKey)
	//用于检查控制符
	//log.Println([]byte(queryDiff.NoBCPubKey))

	//本地不用先访问crl,因为添加进crl的时候，删除了cert
	NoBCClientCert,err:=certdb.DbCert.Get(NoBCPubKey)
	fmt.Println(NoBCClientCert)
	if err!=nil{
		resp.Status=err.Error()
	}else{
		//log.Println(NoBCClientCert)
		resp.Status="ok"
	}
	resp.Key=NoBCPubKey
	resp.Cert=NoBCClientCert
	//resp.Status="ok"
	data,err:=json.Marshal(resp)
	fmt.Println(string(data))
	if err!=nil{
		log.Println(err)
	}else{
		_,err=w.Write(data)
		if err!=nil{
			log.Println(err)
		}
	}
}