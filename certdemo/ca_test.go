package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
	"crypto/x509"
	"crypto/x509/pkix"
)

func origin_test() {
	// 生成ecdsa
	e := &ecdsaGen{curve: elliptic.P256()}
	priKey, _ := e.KeyGen()
	priKeyEncode, err := x509.MarshalECPrivateKey(priKey)
	checkError(err)
	// 保存到pem文件
	f, err := os.Create("ec.pem")
	checkError(err)
	pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: priKeyEncode})
	f.Close()
	pubKey := priKey.Public()
	// Encode public key
	//raw, err := x509.MarshalPKIXPublicKey(pubKey)
	//checkError(err)
	//log.Info(raw)

	// 自签
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	expiry := 365 * 24 * time.Hour
	notBefore := time.Now().Add(-5 * time.Minute).UTC()
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Locality:           []string{"zhongguancun"},
			Province:           []string{"Beijing"},
			OrganizationalUnit: []string{"tect"},
			Organization:       []string{"paradise"},
			StreetAddress:      []string{"street", "address", "demo"},
			PostalCode:         []string{"310000"},
			CommonName:         "demo.example.com",
		},
	}
	template.SubjectKeyId = priKeyHash(priKey)

	x509certEncode, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, priKey)
	checkError(err)
	crt, err := os.Create("cert.crt")
	checkError(err)
	pem.Encode(crt, &pem.Block{Type: "CERTIFICATE", Bytes: x509certEncode})
	crt.Close()

	// 使用bob的密钥进行证书签名
	bobPriKey, _ := e.KeyGen()
	bobPriKeyEncode, err := x509.MarshalECPrivateKey(bobPriKey)
	checkError(err)
	bobf, err := os.Create("bob.pem")
	checkError(err)
	pem.Encode(bobf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bobPriKeyEncode})
	bobf.Close()

	bobPubKey := bobPriKey.Public()
	bobSerialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	notBefore = time.Now().Add(-5 * time.Minute).UTC()
	bobTemplate := x509.Certificate{
		SerialNumber:          bobSerialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Locality:           []string{"Locality"},
			Province:           []string{"Beijing"},
			OrganizationalUnit: []string{"tect"},
			Organization:       []string{"paradise"},
			StreetAddress:      []string{"street", "address", "demo"},
			PostalCode:         []string{"310000"},
			CommonName:         "demo.example.com",
		},
	}
	bobTemplate.SubjectKeyId = priKeyHash(bobPriKey)
	parent, err := x509.ParseCertificate(x509certEncode)
	checkError(err)
	bobCertEncode, err := x509.CreateCertificate(rand.Reader, &bobTemplate, parent, bobPubKey, priKey)
	checkError(err)

	bcrt, _ := os.Create("bob.crt")
	pem.Encode(bcrt, &pem.Block{Type: "CERTIFICATE", Bytes: bobCertEncode})
	bcrt.Close()
}


func Client_test(){
	// 使用bob的密钥进行证书签名
	e := &ecdsaGen{curve: elliptic.P256()}
	bobPriKey, _ := e.KeyGen()
	bobPriKeyEncode, err := x509.MarshalECPrivateKey(bobPriKey)
	checkError(err)
	bobf, err := os.Create("bob.pem")
	checkError(err)
	pem.Encode(bobf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bobPriKeyEncode})
	bobf.Close()

	bobPubKey := bobPriKey.Public()
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	//serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	expiry := 365 * 24 * time.Hour
	notBefore := time.Now().Add(-5 * time.Minute).UTC()

	bobSerialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	notBefore = time.Now().Add(-5 * time.Minute).UTC()
	bobTemplate := x509.Certificate{
		SerialNumber:          bobSerialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Locality:           []string{"Locality"},
			Province:           []string{"Beijing"},
			OrganizationalUnit: []string{"tect"},
			Organization:       []string{"paradise"},
			StreetAddress:      []string{"street", "address", "demo"},
			PostalCode:         []string{"310000"},
			CommonName:         "demo.example.com",
		},
	}
	bobTemplate.SubjectKeyId = priKeyHash(bobPriKey)
	crt, err := os.Open("cert.crt")
	defer crt.Close()

	buf:=make([]byte,2048)
	n,err:=crt.Read(buf)
	fmt.Println(string(buf[:n]))

	block, _ := pem.Decode([]byte(buf[:n]))
	//here
	fmt.Println(block)
	fmt.Println(block.Type)
	x509certEncode := block.Bytes
	//priKey, _ := x509.ParseECPrivateKey(x509certEncode)

	parent, err := x509.ParseCertificate(x509certEncode)
	checkError(err)


	pri,err:=os.Open("ec.pem")
	defer pri.Close()
	n,err =pri.Read(buf)
	fmt.Println(string(buf[:n]))

	block, _ = pem.Decode([]byte(buf[:n]))
	priKey,err:=x509.ParseECPrivateKey(block.Bytes)
	/*
	e := &ecdsaGen{curve: elliptic.P256()}
	priKey, _ := e.KeyGen()
	priKeyEncode, err := x509.MarshalECPrivateKey(priKey)
	*/
	checkError(err)

	//pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}



	bobCertEncode, err := x509.CreateCertificate(rand.Reader, &bobTemplate, parent, bobPubKey, priKey)
	checkError(err)

	bcrt, _ := os.Create("client.crt")
	pem.Encode(bcrt, &pem.Block{Type: "CERTIFICATE", Bytes: bobCertEncode})
	bcrt.Close()
}

func test(){
	CA()
	e2 := &ecdsaGen{curve: elliptic.P256()}
	bobPriKey2, _ := e2.KeyGen()
	bobPriKeyEncode2, _ := x509.MarshalECPrivateKey(bobPriKey2)
	bufkey :=new(bytes.Buffer)
	pem.Encode(bufkey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bobPriKeyEncode2})

	Client(bufkey.String(),
		[]string{"CN"},[]string{"Locality"},[]string{"Beijing"},
		[]string{"test"},[]string{"paradise"},[]string{"street","address","demo"},
		[]string{"310000"},"demo.example.com")
}
