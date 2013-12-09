package main

// Thanks to the folks behind
// http://www.zytrax.com/tech/survival/ssl.html which helped me make
// sense of x509 certs!

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
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"time"
)

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

func SpkacToPublicRsa(spkac SignedPublicKeyAndChallenge) (pub rsa.PublicKey, err error) {
	// TODO(justinabrahms): Digging into collaborators? Or just dumb object access?
	clientPubRsaInterface, err := x509.ParsePKIXPublicKey(spkac.PublicKeyAndChallenge.Spki.Raw)
	if err != nil {
		return
	}

	pub, ok := clientPubRsaInterface.(*rsa.PublicKey)
	if !ok {
		err = errors.New("Was unable to convert the Public Key interface to the rsa Type.")
		return
	}
}

func handleCert(w http.ResponseWriter, req *http.Request, serverPrivateRsa *rsa.PrivateKey, serverCert *x509.Certificate) {
	if err := req.ParseForm(); err != nil {
		io.WriteString(w, fmt.Sprintf("Error parsing form: %s", err))
		return
	}

	fmt.Printf("Got the request with params: %s\n", req.Form)

	clientPubkey := req.FormValue("pubkey")
	// username := req.FormValue("username")
	// email := req.FormValue("email")

	spkac, err := StringToSPKAC(clientPubkey)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("%s", err))
		return
	}
	clientPubRsa, err := SpkacToPublicRsa(spkac)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("Unable to convert the signed public key to a public RSA. %s", err))
		return
	}

	// What's the role of challenge? Is that like a csrf token or similar?

	// TODO(justinabrahms): Not in love with this certificate
	// generation being here. I'd prefer it in a method, but can't
	// think of a way that is overridable and nice without having
	// a ton of parameters.

	certStart := time.Now()
	certExpire := certStart.Add(365 * 24 * time.Hour)

	// TODO(justinabrahms): Figure out what these items actually mean instead of copypasta.
	template := x509.Certificate{
		// TODO(justinabrahms): I should really have an Issuer: pkix.Name{} here, for validation purposes.
		// ^^ Maybe only important if I have a legitimately signed cert?
		// Somehow information in Issuer and stuff in the Subject may need to be the same?

		// SerialNumber should be unique, as it's used for revokation purposes.
		SerialNumber: new(big.Int).SetInt64(0),

		// TODO(justinabrahms): Subject should generate a
		// CommonName thing here which points to the userid
		// somehow. Another possibility would be something
		// like: www.example.com/emailAddress=foo@example.org
		// (I don't think they need to be the same)

		Subject: pkix.Name{
			Organization: []string{"Justin Abrahm's silly test."},
		},
		NotBefore: certStart,
		NotAfter:  certExpire,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(nil, &template, serverCert, clientPubRsa, serverPrivateRsa)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("Unable to create certificate. %s\n\n", err))
		return
	}

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

func certFromPem(certBytes []byte) (cert *x509.Certificate, err error) {
	// TODO(justinabrahms): PEMs may be encrpyted?
	block, _ := pem.Decode(certBytes)
	cert, err = x509.ParseCertificate(block.Bytes)
	return
}

func privFromString(privKey string) (serverPrivRsa *rsa.PrivateKey, err error) {
	serverPrivBlock, _ := pem.Decode([]byte(privKey))
	serverPrivRsa, err = x509.ParsePKCS1PrivateKey(serverPrivBlock.Bytes)
	return
}

// starts an http server which listens for posts, returning a
// certificate or error.
func main() {
	flag.Parse()

	myPrivKey, err := ioutil.ReadFile(*privateKeyFile)
	if err != nil {
		log.Fatalf("Unable to read contents of private key file. %s", err)
	}

	certContents, err := ioutil.ReadFile(*certFile)
	if err != nil {
		log.Fatalf("Unable to read contents of certification file. %s", err)
	}

	myCert, err := certFromPem(certContents)
	if err != nil {
		log.Fatalf("Unable to read contents of public key file. %s", err)
	}

	serverPrivateKey, err := privFromString(string(myPrivKey))
	if err != nil {
		log.Fatalf("Unable to read server's private key. %s", err)
	}

	http.HandleFunc("/", index)
	http.HandleFunc("/gen-key", func(w http.ResponseWriter, req *http.Request) {
		handleCert(w, req, serverPrivateKey, myCert)
	})

	port := 8001
	ip := "0.0.0.0"
	fmt.Printf("Listening on port %d\n", port)
	// TODO(justinabrahms): Move this to TLS
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", ip, port), nil); err != nil {
		log.Fatal("Could not listen for requests: ", err)
	}
}
