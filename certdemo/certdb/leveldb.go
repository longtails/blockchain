package certdb

import (
	"blockchain/certdemo/certifacte"
	"fmt"

	//"blockchain/certdemo/certifacte"
	"crypto/x509"
	"encoding/pem"
	"github.com/syndtr/goleveldb/leveldb"
	"log"
	"sync"
)

var DbCert,DbCRL,DbKey CERTDB
func init(){
	DbCert.Open("./dbcert")
	DbCRL.Open("./dbcrl")
	DbKey.Open("./dbkey")
}
type CERTDB struct{
	db *leveldb.DB
	stop bool
	mux sync.Mutex
}

func (cdb*CERTDB)Open(path string){
	db,err := leveldb.OpenFile(path, nil)
	if err!=nil{
		panic(err)
	}
	cdb.db=db
}
func (cdb*CERTDB)Close() {
	cdb.stop=true
	for err:=cdb.db.Close();err!=nil;{
		log.Println("close certdb again!")
	}
}
func (cdb*CERTDB)check(){
	if cdb.stop==true{
		return
	}
}
type F func(db*leveldb.DB)()
/*
负责重新生成证书*/
func (cdb*CERTDB)Deal(f func(db*leveldb.DB)){
	log.Println("deal func")
	///cdb.mux.Lock()
	f(cdb.db)
	//cdb.mux.Unlock()
}

func (cdb *CERTDB)Put(key,value string)error{
	log.Println("in put")
	cdb.mux.Lock()
	err:=cdb.db.Put([]byte(key),[]byte(value),nil)
	cdb.mux.Unlock()
	return err
}

func (cdb *CERTDB)Get(key string)(string,error){
	cdb.mux.Lock()
	val,err:=cdb.db.Get([]byte(key),nil)
	cdb.mux.Unlock()
	return string(val),err
}
//获取一批key
//attention: n can not be too big
func (cdb *CERTDB)GetSomeKeys(n int)(keys []string){
	cdb.mux.Lock()
	iter := cdb.db.NewIterator(nil, nil)
	for iter.Next()&&n>0 {
		key := iter.Key()
		keys=append(keys,string(key))
		n--
	}
	cdb.mux.Unlock()
	return keys
}

func (cdb *CERTDB)Del(key string)error{
	cdb.mux.Lock()
	err:=cdb.db.Delete([]byte(key),nil)
	cdb.mux.Unlock()
	return err
}



//test
func T1(db *leveldb.DB){
	log.Println("gen new cert")
	iter := db.NewIterator(nil, nil)
	//这里边不能再加锁了
	for iter.Next() {
		prikey := iter.Key()
		log.Println(string(prikey))
		clientcert := iter.Value()
		log.Println("cert:",string(clientcert))
		block, _ := pem.Decode([]byte(clientcert))
		cert,err:=x509.ParseCertificate(block.Bytes)
		if err!=nil{
			log.Println(err)
		}
		certstr:=certifacte.Client(string(prikey),cert.Subject.Country,cert.Subject.Locality,cert.Subject.Province,cert.Subject.OrganizationalUnit,
			cert.Subject.Organization,cert.Subject.StreetAddress,cert.Subject.PostalCode,cert.Subject.CommonName)
		log.Println(certstr)
		err=db.Put(prikey,[]byte(certstr),nil)
		//err=db.Put(string(prikey),certstr)
		//更新data
		log.Println(err)
	}
	iter.Release()
}
func (db*CERTDB)Show(){
	iter := db.db.NewIterator(nil, nil)
	db.mux.Lock()
	for iter.Next(){
		key:=iter.Key()
		value:=iter.Value()
		str:=string(key)
		if str[len(str)-1]=='\n'{
			fmt.Println("last is \\n")
		}
		log.Println(string(key),string(value))
	}
	db.mux.Unlock()
}
