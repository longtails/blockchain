package test

import (
	"blockchain/certdemo/certdb"
	. "blockchain/certdemo/certifacte"
	"bytes"
	crand "crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/pem"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"log"
	"os"
	"os/exec"
	"time"
	"crypto/x509"
)

func main() {
	fmt.Println("add 1000")
	write1000()
	//TestExpired()
}
func write1000(){
	for i:=0;i<1000;i++{
		writeKey()
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
func clientKey1() (string,string){
	//私钥
	e2 := &ecdsaGen{curve: elliptic.P256()}
	clientPriKey,_ := e2.KeyGen()
	clientPriKeyEncode, _ := x509.MarshalECPrivateKey(clientPriKey)
	bufKey := new(bytes.Buffer)
	err :=pem.Encode(bufKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: clientPriKeyEncode})
	if err!=nil{
		fmt.Println(err)
	}
	 var ClientKey struct{
		PriKey string
		PubKey string
		URL string
	}

	ClientKey.PriKey=string(bufKey.Bytes())
	//公钥
	clientPubKey := clientPriKey.Public()
	clientPubKeyEncode, _ := x509.MarshalPKIXPublicKey(clientPubKey)
	bufKey.Reset()
	err =pem.Encode(bufKey, &pem.Block{Type: "EC Public KEY", Bytes: clientPubKeyEncode})
	if err!=nil{
		fmt.Println(err)
	}
	ClientKey.PubKey=string(bufKey.Bytes())
	return ClientKey.PriKey,ClientKey.PubKey
}
func writeKey(){
		//update root cert
		crt, err := os.Open("cert.crt")
		defer crt.Close()
		buf := make([]byte, 2048)
		n, err := crt.Read(buf)
		var profile struct {
		ClientKey                                         string
		Country, Locality, Province, OrgUnit, Org, Street string
		PostalCode, CommonName                            string
		ClientCert, RootCert, VerifyResp                  string
		URL string
		}
		profile.RootCert = string(buf[:n])  //读取到根证书

		var pubkey string
		profile.ClientKey,pubkey =clientKey1() //生成客户端key
		fmt.Println(pubkey)

		log.Println("GEN:")
		profile.ClientCert = Client(profile.ClientKey,
			[]string{profile.Country}, []string{profile.Locality}, []string{profile.Province},
			[]string{profile.OrgUnit}, []string{profile.Org}, []string{profile.Street},
			[]string{profile.PostalCode}, profile.CommonName)
		//put into db

		block, _ := pem.Decode([]byte(profile.ClientKey))
		priKey, err := x509.ParseECPrivateKey(block.Bytes)
		pubKey := priKey.Public()
		key,err:=x509.MarshalPKIXPublicKey(pubKey)


		bufs := new(bytes.Buffer)
		err=pem.Encode(bufs, &pem.Block{Type: "EC Public KEY", Bytes: key})
		if err!=nil{
			log.Println(err)
		}
		pkstr:=string(bufs.Bytes())
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
		pubKeyStr:=string(bufs.Bytes())

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


}

func ExSelect() {
	for {
		select {
		//改成配置文件的 todo
		case <-time.After(10 * time.Second):
			log.Println("timeout: gen cert")
		}
	}
}
func TestExpired() {
	certdb.DbCert.Deal(certdb.T1)
}

func TestGetAll() {
	certdb.DbCert.Show()
	return
	//需要只读模式
	db, err := leveldb.OpenFile("./dbcert", nil)

	//defer db.Close()
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	iter := db.NewIterator(nil, nil)
	//这里边不能再加锁了
	for iter.Next() {
		pubkey := iter.Key()
		val := iter.Value()
		//更新data
		log.Println(string(pubkey))
		log.Println(string(val))
	}
	iter.Release()
}
func TestGet() {
	cert, err := certdb.DbCert.Get(`-----BEGIN EC Public KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvJWnkVzQu5YwW+demNt9Zv8n5TAo
VOBq4Q3YrnPJ7UWEwmSxmWpWSZLJb2Cc+oAbUsGe1NaeUkFs/+P94po/vg==
-----END EC Public KEY-----`)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(cert)

}
