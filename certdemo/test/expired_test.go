package test

import (
	"blockchain/certdemo/certdb"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"log"
	"time"
)

func main() {
	fmt.Println("test expired ")
	Expired()
}

func ExpiredSelect() {
	for {
		select {
		//改成配置文件的 todo
		case <-time.After(10 * time.Second):
			log.Println("timeout: gen cert")
		}
	}
}
func Expired() {
	certdb.DbCert.Deal(certdb.T1)
}

func GetAll() {
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
func Get() {
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
