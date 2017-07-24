package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
)

func main() {
	keyIdNeeded := flag.Bool("keyid", false, "prefix with public key ID (e.g. 'rsa2048/')")
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("ERROR: expected exactly 1 domain but got ", flag.NArg())
	}
	domain := flag.Arg(0)

	leaf, err := trustedLeafCertificateFromDomain(domain)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}

	if *keyIdNeeded {
		printKeyId(leaf)
	}
	printEncodedHash(leaf)
}

func trustedLeafCertificateFromDomain(domain string) (*x509.Certificate, error) {
	conn, err := net.Dial("tcp", domain+":443")
	if err != nil {
		return nil, err
	}

	config := tls.Config{ServerName: domain}
	tlsConn := tls.Client(conn, &config)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()
	return state.VerifiedChains[0][0], nil
}

func printKeyId(leaf *x509.Certificate) {
	publicKeyId := publicKeyIdFromX509(leaf)
	fmt.Printf("%v/", publicKeyId)
}

func publicKeyIdFromX509(leaf *x509.Certificate) string {
	if leaf.PublicKeyAlgorithm == x509.RSA {
		public := leaf.PublicKey.(*rsa.PublicKey)
		return fmt.Sprintf("rsa%d", public.N.BitLen())
	}
	log.Fatal("ERROR: unsupported algorithm ", leaf.PublicKeyAlgorithm)
	return ""
}

func printEncodedHash(c *x509.Certificate) {
	spki := c.RawSubjectPublicKeyInfo
	hash := sha256.Sum256(spki)

	fmt.Printf("sha256/%s\n", base64.StdEncoding.EncodeToString(hash[:]))
}
