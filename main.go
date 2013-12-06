package main

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

// important that these two certs are different, else someone could
// maybe masqureade as you, through delegation, I think?
// var authCertPriv = nil
// var authCertPub = nil
var privateKeyFile = flag.String("private-key-file", "", "Private key used to sign the certificate")
var certFile = flag.String("cert-file", "", "Public key used to sign the certificate")

type SubjectPublicKeyInfo struct {
	Raw                 asn1.RawContent
	EncryptionMechanism pkix.AlgorithmIdentifier
	PublicKey           asn1.BitString
}

type PublicKeyAndChallenge struct {
	Spki      SubjectPublicKeyInfo
	Challenge string
}

type SignedPublicKeyAndChallenge struct {
	PublicKeyAndChallenge PublicKeyAndChallenge
	SignatureAlgorithm    pkix.AlgorithmIdentifier
	Signature             asn1.BitString
}

func StringToSPKAC(b64hash string) (cert SignedPublicKeyAndChallenge, err error) {
	outbuf, err := base64.StdEncoding.DecodeString(b64hash)
	if err != nil {
		return cert, errors.New(fmt.Sprintf("Couldn't b64decode pubkey: %s", err))
	}

	_, err = asn1.Unmarshal(outbuf, &cert)
	if err != nil {
		return cert, errors.New(fmt.Sprintf("Errors while unmarshalling payload: %s\n", err))
	}
	return
}

func handleCert(w http.ResponseWriter, req *http.Request, privKey, pubKey string) {
	// get posted username
	// get email
	// generate key request
	// sign key
	if err := req.ParseForm(); err != nil {
		io.WriteString(w, fmt.Sprintf("Error parsing form: %s", err))
		return
	}

	fmt.Printf("Got the request with params: %s\n", req.Form)

	// apparently this pubkey+challenge is DER encoded, signed,
	// then b64'd. I'm not sure if this is actually important for
	// my purposes. Because it's signed, I can't possibly get the
	// original key. b64 decoding might be important, however.

	clientPubkey := req.FormValue("pubkey")
	// username := req.FormValue("username")
	// email := req.FormValue("email")

	serverPrivBlock, _ := pem.Decode([]byte(privKey))

	// TODO(justinabrahms): PEMs may be encrpyted?
	block, _ := pem.Decode([]byte(pubKey))

	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("Can't parse cert: ", err))
		return
	}

	serverPrivRsa, err := x509.ParsePKCS1PrivateKey(serverPrivBlock.Bytes)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("Couldn't load server's RSA key: %s", err))
		return
	}

	spkac, err := StringToSPKAC(clientPubkey)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("%s", err))
		return
	}

	// What's the role of challenge? Is that like a csrf token or similar?

	// pemBlock := pem.Block{
	// 	Bytes: spkac.PublicKeyAndChallenge.Spki.PublicKey.Bytes,
	// 	Type:  "RSA PUBLIC KEY",
	// }
	// pem.Encode(w, &pemBlock)

	// TODO(justinabrahms): Digging into collaborators? Or just dumb object access?
	clientPubRsaInterface, err := x509.ParsePKIXPublicKey(spkac.PublicKeyAndChallenge.Spki.Raw)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("Error parsing public key: %s\n\n", err))
		return
	}

	clientPubRsa, ok := clientPubRsaInterface.(*rsa.PublicKey)
	if !ok {
		io.WriteString(w, "Error in typecast to a public key")
		return
	}

	certStart := time.Now()
	certExpire := certStart.Add(365 * 24 * time.Hour)

	// TODO(justinabrahms): Figure out what these items actually mean instead of copypasta.
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			Organization: []string{"Justin Abrahm's silly test."},
		},
		NotBefore: certStart,
		NotAfter:  certExpire,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// use the _ below, rather than ignoring it.
	cert, err := x509.CreateCertificate(nil, &template, serverCert, clientPubRsa, serverPrivRsa)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("Unable to create certificate. %s\n\n", err))
		return
	}

	// io.WriteString(w, fmt.Sprintf("omg. I have a cert. %v", cert))

	// // should respond with a Content-Type of  "application/x-x509-user-cert"
	// // and a body of the signed key
	// resp := fmt.Sprintf("ohai!\n\nFound:\n\tKey:%s\n\tusername:%s\n\temail:%s\n", clientPubkey, username, email)
	// io.WriteString(w, resp)
	w.Header().Set("Content-Type", "application/x-x509-user-cert")
	w.Write(cert)
}

func ContainsValidKey(req *http.Request) bool {
	// should inspect the request for the public key.
	return false
}

func index(w http.ResponseWriter, req *http.Request) {
	if ContainsValidKey(req) {
		// TODO(justinabrahms): this shouldn't return a bool,
		// but rather info from inside the key?
		io.WriteString(w, "Looks like you're authed. Congrats!")
		return
	}

	// TODO(justinabrahms): conditionally 302 to login page.
	// TODO(justinabrahms): Move this somewhere less in the way.
	io.WriteString(w, `
<!DOCTYPE html>
<html>
<h1>Let's generate you a cert so you don't have to use a password!</h1>
 Hit the Generate button and then install the certificate it gives you in your browser.
 All modern browsers (except for Internet Explorer) should be compatible.
 <form method="post" action="/gen-key">
   <keygen name="pubkey" challenge="">
   <input name="email" value="a-user-here@example.com">
   The username I want: <input type="text" name="username" value="Alice">
   <input type="submit" name="createcert" value="Generate">
 </form>
 <strong>Wait a minute, then refresh this page over HTTPS to see your new cert in action!</strong>
</html>
`)
}

func fileToString(filename string) (string, error) {
	var contents []byte
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = io.ReadFull(file, contents)
	if err != nil {
		return "", err
	}

	return string(contents), nil
}

// starts an http server which listens for posts, returning a
// certificate or error.
func main() {
	flag.Parse()

	myPrivKey, err := fileToString(*privateKeyFile)
	if err != nil {
		log.Fatalf("Unable to read contents of private key file.")
	}

	myCert, err := fileToString(*certFile)
	if err != nil {
		log.Fatalf("Unable to read contents of public key file.")
	}

	// TODO(justinabrahms): Move this to TLS
	http.HandleFunc("/", index)

	// TODO(justinabrahms): Should consider moving this anonymous function to a gorilla context or similar?
	http.HandleFunc("/gen-key", func(w http.ResponseWriter, req *http.Request) {
		handleCert(w, req, myPrivKey, myCert)
	})

	port := 8001
	ip := "0.0.0.0"
	fmt.Printf("Listening on port %d\n", port)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", ip, port), nil); err != nil {
		log.Fatal("Could not listen for requests: ", err)
	}
}
