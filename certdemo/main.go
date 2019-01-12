package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path"
	"time"

	"crypto/sha256"
	"github.com/Sirupsen/logrus"
	"html/template"
)

var log = logrus.New()

type ecdsaGen struct {
	curve elliptic.Curve
}

func (e *ecdsaGen) KeyGen() (key *ecdsa.PrivateKey, err error) {
	privKey, err := ecdsa.GenerateKey(e.curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	// 将ec 密钥写入到 pem文件里
	keypem, _ := os.OpenFile("ec-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	pem.Encode(keypem, &pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded), string(pemEncodedPub)
}

func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}

func checkError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

// 根据ecdsa密钥生成特征标识码
func priKeyHash(priKey *ecdsa.PrivateKey) []byte {
	hash := sha256.New()
	hash.Write(elliptic.Marshal(priKey.Curve, priKey.PublicKey.X, priKey.PublicKey.Y))
	return hash.Sum(nil)
}


func CA(){
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

}
//func Client(x509certEncode []byte,priKey *ecdsa.PrivateKey,
func Client(clientKey string,
			country,locality,province,orgunit,org,street,postalcode []string,
			commonName string)string{

	// 使用bob的密钥进行证书签名
	bobf, err := os.Create("bob.pem")
	bobf.Write([]byte(clientKey))
	checkError(err)

	block, _ := pem.Decode([]byte(clientKey))
	bobPriKey,err:=x509.ParseECPrivateKey(block.Bytes)
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
			Country:            country,
			Locality:           locality,
			Province:           province,
			OrganizationalUnit: orgunit,
			Organization:       org,
			StreetAddress:      street,
			PostalCode:         postalcode,
			CommonName:         commonName,
		},
	}
	bobTemplate.SubjectKeyId = priKeyHash(bobPriKey)
	crt, err := os.Open("cert.crt")
	defer crt.Close()

	buf:=make([]byte,2048)
	n,err:=crt.Read(buf)
	//fmt.Println(string(buf[:n]))

	block, _ = pem.Decode([]byte(buf[:n]))
	//here
	x509certEncode := block.Bytes
	//priKey, _ := x509.ParseECPrivateKey(x509certEncode)

	parent, err := x509.ParseCertificate(x509certEncode)
	checkError(err)


	pri,err:=os.Open("ec.pem")
	defer pri.Close()
	n,err =pri.Read(buf)
	//fmt.Println(string(buf[:n]))

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

	bcrt, _ := os.Create("bob.crt")
	bufcrt:=new(bytes.Buffer)
	pem.Encode(bufcrt, &pem.Block{Type: "CERTIFICATE", Bytes: bobCertEncode})
	bcrt.Write(bufcrt.Bytes())
	bcrt.Close()
	log.Println("new crt:\n",bufcrt)
	return bufcrt.String()
}

func verify(rootPEM ,certPEM string)(bool,error) {
	// Verifying with a custom list of root certificates.
	log.Println("verifying")
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return false,errors.New("failed to parse root certificate")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false,errors.New("failed to parse root certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false,errors.New("failed to parse certificate: " + err.Error())
	}
	opts := x509.VerifyOptions{
		Roots:   roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return false,errors.New("failed to verify certificate: " + err.Error())
	}
	return true,nil
}
func init(){
	f,err:=os.Open("cert.crt")
	defer f.Close()
	if err!=nil{
		log.Println("ca cert does not exist!gen one")
		CA()
	}else{
		log.Println("ca cert exist!")
	}
}
func main(){
	web()
}
func web(){
	//匿名函数注册路由
	http.HandleFunc("/",func(w http.ResponseWriter,r *http.Request) {
		err:=r.ParseForm()
		log.Println(err)
		fp := path.Join("templates", "page1.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type Profile struct {
			URL string
			Show string
		}
		profile:=Profile{r.Host,r.Host}
		if err := tmpl.Execute(w, profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		//w.Write([]byte(data))
	} )
	http.HandleFunc("/register",register)
	log.Println("starting service!")

	//log.Fatal输出后，会退出程序,执行os.Exit(1)
	log.Fatal(http.ListenAndServe(":4000",nil))
}
type Profile struct {
	ClientKey string
	Country,Locality,Province,OrgUnit,Org,Street string
	PostalCode,CommonName string
	ClientCert,RootCert,VerifyResp string
}

var profile=Profile{"",
	"","","","",
	"","","","",
	"","",""}

func register(w http.ResponseWriter,r *http.Request){
	//w.Write([]byte("byte byte"))

	fp := path.Join("templates", "page2.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//gen cert
	r.ParseForm()
	tForm:=make(map[string]string)
	if r.Form["action"]==nil||len(r.Form["action"])==0{

		if err := tmpl.Execute(w, profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	    }

		return
	}
	for a,b:=range r.Form{
		if len(b)==0{
			//fmt.Println("a:",a,"b:","null")
			tForm[a]=""
		}else{
			tForm[a]=b[0]
		}
	}

	//update root cert
	crt, err := os.Open("cert.crt")
	defer crt.Close()
	buf:=make([]byte,2048)
	n,err:=crt.Read(buf)
	profile.RootCert=string(buf[:n])



	if tForm["action"]=="GEN" {
		log.Println("GEN:")
		profile.ClientKey=tForm["clientkey"]
		profile.Country=tForm["country"]
		profile.Locality=tForm["locality"]
		profile.Province=tForm["province"]
		profile.Org=tForm["org"]
		profile.OrgUnit=tForm["orgunit"]
		profile.Street=tForm["street"]
		profile.PostalCode=tForm["postalocde"]
		profile.CommonName=tForm["commonname"]
		profile.ClientCert=tForm["clientcert"]
		//profile.RootCert=tForm["rootcert"]
		profile.VerifyResp=tForm["verifyresp"]

		profile.ClientCert = Client(profile.ClientKey,
			[]string{profile.Country}, []string{profile.Locality}, []string{profile.Province},
			[]string{profile.OrgUnit}, []string{profile.Org}, []string{profile.Street},
			[]string{profile.PostalCode}, profile.CommonName)

		//put into bc
		//cmd := exec.Command("./putclientcert.sh",profile.ClientKey,profile.ClientCert)
		cmd := exec.Command("curl","-X","POST","--data-urlencode","car_key="+profile.ClientKey,
			"--data-urlencode","car_ca="+profile.ClientCert,
			"-d","action=set_Car_CA",
			"http://114.115.165.101:10000/invoke/set_Car_CA")
		log.Printf("Running command and waiting for it to finish...")
		err := cmd.Run()
		if err!=nil{
			log.Printf("Command finished with error: %v", err)
			profile.VerifyResp="write into block error,please retry:"+err.Error()
		}else{
			log.Printf("Command finished successfully")
		}

	}else if tForm["action"]=="verify"{
		log.Println("verify")
		if ok,err:=verify(profile.RootCert,profile.ClientCert);!ok{
			profile.VerifyResp=err.Error()
		}else{
			profile.VerifyResp="ok"
		}
	}


	if err := tmpl.Execute(w, profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

