package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/hyperboloide/lk"
)

// create a license document:
type MyLicence struct {
	Expires    time.Time
	MacAddress string
}

func main() {

	macAddresses, _ := getMacAddr()

	privateKey, err := lk.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	doc := MyLicence{
		time.Now().Add(time.Minute * 60),
		macAddresses[0],
	}

	// marshall the document to json bytes:
	docBytes, err := json.Marshal(doc)
	if err != nil {
		log.Fatal(err)
	}

	// generate your license with the private key and the document:
	license, err := lk.NewLicense(privateKey, docBytes)
	if err != nil {
		log.Fatal(err)
	}

	// encode the new license to b64, this is what you give to your customer.
	str64, err := license.ToB64String()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(str64)

	// get the public key. The public key should be hardcoded in your app to check licences.
	// Do not distribute the private key!
	publicKey := privateKey.GetPublicKey()

	// validate the license:
	if ok, err := license.Verify(publicKey); err != nil {
		log.Fatal(err)
	} else if !ok {
		log.Fatal("Invalid license signature")
	}

	// unmarshal the document and check the end date:
	res := MyLicence{}
	if err := json.Unmarshal(license.Data, &res); err != nil {
		log.Fatal(err)
	} else if res.Expires.Before(time.Now()) {
		log.Fatalf("License expired on: %s", res.Expires.String())
	} else {
		fmt.Printf(`Licensed until %s for device %s \n`, res.Expires.Format("02-Jan-2006 15:04:05"), res.MacAddress)
	}
}

func getMacAddr() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as, nil
}
