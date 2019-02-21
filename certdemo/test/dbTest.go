package main

import (
	"blockchain/certdemo/certdb"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
)

func main(){
	fmt.Println(certdb.DbKey.GetSomeKeys(10))
}
func Show() {
	db,err := leveldb.OpenFile("../dbcert", nil)
	if err!=nil{
		panic(err)
	}
	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()
		fmt.Println(string(key), string(value))
	}
}
