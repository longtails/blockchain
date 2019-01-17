package certdb

import (
	"github.com/syndtr/goleveldb/leveldb"
	"log"
	"sync"
	"testing"
	"time"
)
func db_new_test(db*leveldb.DB,mux sync.Mutex){
	mux.Lock()
	iter := db.NewIterator(nil, nil)
	//这里边不能再加锁了
	for iter.Next(){
		key:=iter.Key()
		value:=iter.Value()
		value=[]byte(string(value)+"2")
		//更新data
		err:=db.Put(key,value,nil)
		//todo 删除过期data
		log.Println(err)
	}
	iter.Release()
	mux.Unlock()
}
func db_show(t*testing.T,db*leveldb.DB,mux sync.Mutex){
	go func(){
		for{
			select {
				case <- time.After(10*time.Second):
					t.Log("timeout:gen new data")
					db_new_test(db,mux)
			}
			t.Log("new one")
		}
	}()
	iter := db.NewIterator(nil, nil)
	mux.Lock()
	for iter.Next(){
		key:=iter.Key()
		value:=iter.Value()
		value=[]byte(string(value)+"2")
		t.Log(string(key),string(value))
	}
	mux.Unlock()
}
func tTestDb(t*testing.T){
	//添加数据
	go db_new_test(DbCert.db,DbCert.mux)
	t.Log("add all")
	_ = DbCert.Put("a","1")
	_= DbCert.Put("b","1")
	_= DbCert.Put("c","1")
	db_show(t,DbCert.db,DbCert.mux)
	val,_:=DbCert.Get("b")
	_= DbCert.Del("b")
	_= DbCRL.Put("b",val)
	t.Log("at cert")
	db_show(t,DbCert.db,DbCert.mux)
	t.Log("at crl")
	db_show(t,DbCRL.db,DbCRL.mux)
	time.Sleep(10*time.Second)
	t.Log("done")
}


func tTestClose(t *testing.T){
	t.Log("CLOSE")
	DbCert.Close()
	go func(db*leveldb.DB,mux sync.Mutex) {
		mux.Lock()
		iter := db.NewIterator(nil, nil)
		//这里边不能再加锁了
		for iter.Next() {
			key := iter.Key()
			value := iter.Value()
			value = []byte(string(value) + "2")
			//更新data
			err := db.Put(key, value, nil)
			//todo 删除过期data
			t.Log(err)
		}
		iter.Release()
		mux.Unlock()
	}(DbCert.db,DbCert.mux)
}

func tTestAdd(t*testing.T){
	err:=DbCert.Put(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGngTglsYk4bvdeNmeRK7kV2Gt61a7v4LAMeymSbQtXuoAoGCCqGSM49
AwEHoUQDQgAENfhEu/qhkCpGglGMeGcmjj5ELHjSK11K37yH9Xgzqan3bVgSj3Fp
LAYoS52/aUG9XM1uuujho68MbO7zgaxb3g==
-----END EC PRIVATE KEY-----`,"abc")
	if err!=nil{
		t.Log(err)
	}
	d,err:=DbCert.Get(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGngTglsYk4bvdeNmeRK7kV2Gt61a7v4LAMeymSbQtXuoAoGCCqGSM49
AwEHoUQDQgAENfhEu/qhkCpGglGMeGcmjj5ELHjSK11K37yH9Xgzqan3bVgSj3Fp
LAYoS52/aUG9XM1uuujho68MbO7zgaxb3g==
-----END EC PRIVATE KEY-----`)
	if err!=nil{
		t.Log(err)
	}
	t.Log(d)
}

