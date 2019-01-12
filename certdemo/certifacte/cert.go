package certifacte

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
	"os"
	"time"

	"crypto/sha256"
	"github.com/Sirupsen/logrus"
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

func CA() {
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
	country, locality, province, orgunit, org, street, postalcode []string,
	commonName string) string {

	// 使用bob的密钥进行证书签名
	bobf, err := os.Create("bob.pem")
	bobf.Write([]byte(clientKey))
	checkError(err)

	block, _ := pem.Decode([]byte(clientKey))
	bobPriKey, err := x509.ParseECPrivateKey(block.Bytes)
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

	buf := make([]byte, 2048)
	n, err := crt.Read(buf)
	//fmt.Println(string(buf[:n]))

	block, _ = pem.Decode([]byte(buf[:n]))
	//here
	x509certEncode := block.Bytes
	//priKey, _ := x509.ParseECPrivateKey(x509certEncode)

	parent, err := x509.ParseCertificate(x509certEncode)
	checkError(err)

	pri, err := os.Open("ec.pem")
	defer pri.Close()
	n, err = pri.Read(buf)
	//fmt.Println(string(buf[:n]))

	block, _ = pem.Decode([]byte(buf[:n]))
	priKey, err := x509.ParseECPrivateKey(block.Bytes)
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
	bufcrt := new(bytes.Buffer)
	pem.Encode(bufcrt, &pem.Block{Type: "CERTIFICATE", Bytes: bobCertEncode})
	bcrt.Write(bufcrt.Bytes())
	bcrt.Close()
	log.Println("new crt:\n", bufcrt)
	return bufcrt.String()
}

func Verify(rootPEM, certPEM string) (bool, error) {
	// Verifying with a custom list of root certificates.
	log.Println("verifying")
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return false, errors.New("failed to parse root certificate")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false, errors.New("failed to parse root certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, errors.New("failed to parse certificate: " + err.Error())
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return false, errors.New("failed to verify certificate: " + err.Error())
	}
	return true, nil
}
