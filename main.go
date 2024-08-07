package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"time"

	"github.com/hyperboloide/lk"
)

// create a license document:
type MyLicence struct {
	Expires    time.Time
	MacAddress string
}

func main() {

	if ok, err := createLicenseFile(); err != nil {
		log.Fatal(err)
	} else if !ok {
		log.Fatal("Create license failed!")
	}

	if ok, err := validateLicenseFile(); err != nil {
		log.Fatal(err)
	} else if !ok {
		log.Fatal("Invalid license!")
	}

	log.Println("License is valid!")
}

func createLicenseFile() (bool, error) {

	privateKey, err := readPrivateKey()

	if err != nil {
		return false, err
	}

	macAddresses, err := getMacAddr()
	if err != nil {
		return false, err
	}

	doc := MyLicence{
		time.Now().Add(time.Minute * 60),
		macAddresses[0],
	}

	// marshall the document to json bytes:
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return false, err
	}

	log.Println("About to generate license for mac address: ", doc.MacAddress)

	// generate your license with the private key and the document:
	license, err := lk.NewLicense(privateKey, docBytes)
	if err != nil {
		return false, err
	}

	// encode the new license to b64, this is what you give to your customer.
	licenseStr, err := license.ToBytes()
	if err != nil {
		return false, err
	}

	err = os.WriteFile("license.dat", licenseStr, 0644)
	if err != nil {
		return false, err
	}

	return true, nil // success

}

func validateLicenseFile() (bool, error) {

	publicKey, err := readPublicKey()

	if err != nil {
		return false, err
	}

	// read the license file:
	licenseDat, err := os.ReadFile("license.dat")
	if err != nil {
		return false, err
	}

	// decode the license from b64:
	license, err := lk.LicenseFromBytes(licenseDat)
	if err != nil {
		return false, err
	}

	// verify the license with the public key:
	if ok, err := license.Verify(publicKey); err != nil {
		return false, err
	} else if !ok {
		return false, fmt.Errorf("invalid license")
	}

	// unmarshall the document:
	var doc MyLicence
	err = json.Unmarshal(license.Data, &doc)
	if err != nil {
		return false, err
	}

	// check the document:
	if doc.Expires.Before(time.Now()) {
		return false, fmt.Errorf("license expired")
	}

	macAddresses, err := getMacAddr()
	if err != nil {
		return false, err
	}

	idx := slices.IndexFunc(macAddresses, func(c string) bool { return c == doc.MacAddress })

	if idx == -1 {
		return false, fmt.Errorf("device not authorized")
	}

	return true, nil
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

func readPrivateKey() (*lk.PrivateKey, error) {

	pk, err := os.ReadFile("private.key")

	if err != nil {
		return nil, err
	}

	privateKey, err := lk.PrivateKeyFromB32String(string(pk))

	if err != nil {
		return nil, err
	}

	return privateKey, nil

}

func readPublicKey() (*lk.PublicKey, error) {

	pk, err := os.ReadFile("public.key")

	if err != nil {
		return nil, err
	}

	publicKey, err := lk.PublicKeyFromB32String(string(pk))

	if err != nil {
		return nil, err
	}

	return publicKey, nil

}
