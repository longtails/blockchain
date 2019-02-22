package main

import (
"encoding/json"
"fmt"
"io/ioutil"
"net/http"
	"net/url"
)
type NoBC struct{
	Status string
	Key string
	Cert string
}
func main(){

	postForm()
	return
	parsejs()

}
func postForm(){
	var NoBCPubKey string=`-----BEGIN EC Public KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+wmZKMQrSnzF0XjCycAjaDo5Ecog
JfuLVvjmpBKhqLd0FQ4RGUjdtV5DzcYN6R74gp6nTlFgTxhIyq0c9vvlKw==
-----END EC Public KEY-----`
	resp,err:=http.PostForm("http://127.0.0.1:5000/queryByNoBC",
		url.Values{
			"pubKey":   {NoBCPubKey},
		})
	if err!=nil{
		fmt.Println(err)
	}
	body,_:=ioutil.ReadAll(resp.Body)
	data:=NoBC{}
	err=json.Unmarshal(body,&data)
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Println(data.Cert)
}
func parsejs(){
	resp,err:=http.Get("http://127.0.0.1:5000/queryByNoBC")
	if err!=nil{
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body,_:=ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	pro:=NoBC{}
	err=json.Unmarshal(body,&pro)
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Println(pro)
}


