package main

import (
	. "blockchain/certdemo/certifacte"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
)

func init() {
	f, err := os.Open("cert.crt")
	defer f.Close()
	if err != nil {
		log.Println("ca cert does not exist!gen one")
		CA()
	} else {
		log.Println("ca cert exist!")
	}
}
func main() {
	web()
}
func web() {
	//匿名函数注册路由
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		log.Println(err)
		fp := path.Join("templates", "page1.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type Profile struct {
			URL  string
			Show string
		}
		profile := Profile{r.Host, r.Host}
		if err := tmpl.Execute(w, profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		//w.Write([]byte(data))
	})
	http.HandleFunc("/register", register)
	log.Println("starting service!")

	//log.Fatal输出后，会退出程序,执行os.Exit(1)
	log.Fatal(http.ListenAndServe(":4000", nil))
}

type Profile struct {
	ClientKey                                         string
	Country, Locality, Province, OrgUnit, Org, Street string
	PostalCode, CommonName                            string
	ClientCert, RootCert, VerifyResp                  string
}

var profile = Profile{"",
	"", "", "", "",
	"", "", "", "",
	"", "", ""}

func register(w http.ResponseWriter, r *http.Request) {
	//w.Write([]byte("byte byte"))

	fp := path.Join("templates", "page2.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//gen cert
	r.ParseForm()
	tForm := make(map[string]string)
	if r.Form["action"] == nil || len(r.Form["action"]) == 0 {

		if err := tmpl.Execute(w, profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		return
	}
	for a, b := range r.Form {
		if len(b) == 0 {
			//fmt.Println("a:",a,"b:","null")
			tForm[a] = ""
		} else {
			tForm[a] = b[0]
		}
	}

	//update root cert
	crt, err := os.Open("cert.crt")
	defer crt.Close()
	buf := make([]byte, 2048)
	n, err := crt.Read(buf)
	profile.RootCert = string(buf[:n])

	if tForm["action"] == "GEN" {
		log.Println("GEN:")
		profile.ClientKey = tForm["clientkey"]
		profile.Country = tForm["country"]
		profile.Locality = tForm["locality"]
		profile.Province = tForm["province"]
		profile.Org = tForm["org"]
		profile.OrgUnit = tForm["orgunit"]
		profile.Street = tForm["street"]
		profile.PostalCode = tForm["postalocde"]
		profile.CommonName = tForm["commonname"]
		profile.ClientCert = tForm["clientcert"]
		//profile.RootCert=tForm["rootcert"]
		profile.VerifyResp = tForm["verifyresp"]

		profile.ClientCert = Client(profile.ClientKey,
			[]string{profile.Country}, []string{profile.Locality}, []string{profile.Province},
			[]string{profile.OrgUnit}, []string{profile.Org}, []string{profile.Street},
			[]string{profile.PostalCode}, profile.CommonName)

		//put into bc
		//cmd := exec.Command("./putclientcert.sh",profile.ClientKey,profile.ClientCert)
		cmd := exec.Command("curl", "-X", "POST", "--data-urlencode", "car_key="+profile.ClientKey,
			"--data-urlencode", "car_ca="+profile.ClientCert,
			"-d", "action=set_Car_CA",
			"http://114.115.165.101:10000/invoke/set_Car_CA")
		log.Printf("Running command and waiting for it to finish...")
		err := cmd.Run()
		if err != nil {
			log.Printf("Command finished with error: %v", err)
			profile.VerifyResp = "write into block error,please retry:" + err.Error()
		} else {
			log.Printf("Command finished successfully")
		}

	} else if tForm["action"] == "verify" {
		log.Println("verify")
		if ok, err := Verify(profile.RootCert, profile.ClientCert); !ok {
			profile.VerifyResp = err.Error()
		} else {
			profile.VerifyResp = "ok"
		}
	}

	if err := tmpl.Execute(w, profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
