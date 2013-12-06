package main

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

// important that these two certs are different, else someone could
// maybe masqureade as you, through delegation, I think?
// var authCertPriv = nil
// var authCertPub = nil

var myCert = `-----BEGIN CERTIFICATE-----
MIIEUTCCAzmgAwIBAgIJAIuAxkQFMCqiMA0GCSqGSIb3DQEBBQUAMHgxCzAJBgNV
BAYTAlVTMQ8wDQYDVQQIEwZPcmVnb24xETAPBgNVBAcTCFBvcnRsYW5kMQwwCgYD
VQQKEwNOL0ExFzAVBgNVBAMTDkp1c3RpbiBBYnJhaG1zMR4wHAYJKoZIhvcNAQkB
Fg9qdXN0aW5AYWJyYWgubXMwHhcNMTMxMjA0MTEwNjA1WhcNMzMxMTI5MTEwNjA1
WjB4MQswCQYDVQQGEwJVUzEPMA0GA1UECBMGT3JlZ29uMREwDwYDVQQHEwhQb3J0
bGFuZDEMMAoGA1UEChMDTi9BMRcwFQYDVQQDEw5KdXN0aW4gQWJyYWhtczEeMBwG
CSqGSIb3DQEJARYPanVzdGluQGFicmFoLm1zMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA0mY7snSPtvD2sW5T9Bh8fg+x5FiJj6J8cwDfiWjnhNggo+wg
hV2AARX7mr7RjlP+2t5xl5G5b32vrW+BN7lzGhovVWMRGavmfbSiR5O8nAQqejtL
MID0ju+xyvifEBzqzf+GckAAsCw8cnOfI3/g4jf5Jn7nFrM6HkGtmDQcAYAXCjbA
y5WURMdB6LYibyF7DKNVHJCcxcF/hyc1urdHV3MxvAxrguC0ofZCe1pRBCQXvPUC
FOxcSmVma08AsvI+KO3pasvyCeO09Ma3oReII3mTg838taLA80GDcLgrZW8/9NrH
fFisJnTtdl0zdejUsSrTT6sryK4z3/uWjCaszwIDAQABo4HdMIHaMB0GA1UdDgQW
BBSa/t+pEc1t4JDC8+nuhJySo+A5qDCBqgYDVR0jBIGiMIGfgBSa/t+pEc1t4JDC
8+nuhJySo+A5qKF8pHoweDELMAkGA1UEBhMCVVMxDzANBgNVBAgTBk9yZWdvbjER
MA8GA1UEBxMIUG9ydGxhbmQxDDAKBgNVBAoTA04vQTEXMBUGA1UEAxMOSnVzdGlu
IEFicmFobXMxHjAcBgkqhkiG9w0BCQEWD2p1c3RpbkBhYnJhaC5tc4IJAIuAxkQF
MCqiMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAGH59bYyChwURveS
mIKczfRlBwlrKkhAoif+ouwb0+SOaFXtUYY+cXGm2z2CSpJNgVOTvIob3WGYmhDB
DD5uBqgHiyCigO/9fDiGYTM8zv0pz40xniExl/v8aecU090/HoNH7YQucTfz7MEz
ouKMU5vD02M/1V57Toy8KTo5he1qQvM1C4oYnz10t+iahY/0y3uMOUEGF52nYYGc
PYrsLpCF7/UZ+dXQFqnlpBh0RXknUAh9vOQjch0mesQdhY4DBOi7GKZdp8EI8SNh
DdrlyW4yBg/+Msek7P0CgCGsCieouz4JoGCzSTkL/xm6nTpqHtwREgjtyO+qbeZi
O/CF+QA=
-----END CERTIFICATE-----`

var myPrivKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA0mY7snSPtvD2sW5T9Bh8fg+x5FiJj6J8cwDfiWjnhNggo+wg
hV2AARX7mr7RjlP+2t5xl5G5b32vrW+BN7lzGhovVWMRGavmfbSiR5O8nAQqejtL
MID0ju+xyvifEBzqzf+GckAAsCw8cnOfI3/g4jf5Jn7nFrM6HkGtmDQcAYAXCjbA
y5WURMdB6LYibyF7DKNVHJCcxcF/hyc1urdHV3MxvAxrguC0ofZCe1pRBCQXvPUC
FOxcSmVma08AsvI+KO3pasvyCeO09Ma3oReII3mTg838taLA80GDcLgrZW8/9NrH
fFisJnTtdl0zdejUsSrTT6sryK4z3/uWjCaszwIDAQABAoIBABdcrLJDCRYqKWpI
MuA+u8wPmBQf1J5zT1hBt5B9an+ws+cft/i3ChiUxUxIdeJU506MNpa64plDnncm
k3WJjQNP9wOHLYXpNX2tyfsip2W3fLP304B+QSmB6f78nkTewR/AiMA05R6quseG
mRwK/gCAcJTasHQv0Hs9lbX5y0ZLLB35Vyis5zhRxmMtQ6T50O/H0H8K31wUTGzy
9tyDPqqBGnUaQeyBZ0mt5j4BzKGWwiRRaKaxnRE+KrgZu7hPVQlC1GRNHRqDsNUj
z1T96jx2OwJwe6qzcr/aFCq7T7IMrpd+hjCxe8eL55Kze+e7+I2Fk7/hXOkN+qY3
6L2u2rECgYEA95FtEXWHeL41zxejBKVsq8hdrRaI3zv+KhPdrYG8EkLb/J6ksTod
7Z1hX2zi1fx7D7lmT0yQXHK0xFr0JvuUwCgmV9nTR+N84BDlMj/mEgWDKZav+sGK
NNwS61lLCqj8eodEkdUj7zMKatzIocvDbbq53lPPD+XUSPeqjZaPsKkCgYEA2ZC6
lprCFrLA6m2ZivniwcWioCX+ympcIpKDRKBVnKg/FahEniYrBWNQHTYTwoktR6aP
HyGinNpa+QSNy+OndlAmG5H5SJxdfzMDB8LgpX2HRAO4Xu0OVFIdCflCwcZABSGz
a2ZGxLlzng29kRgV+8oBUsp/zkQOPVxjgW1+xLcCgYAxoROuVlNMH0WGOITTn54D
ae1tj4Dsz4gKQ2VDLSjYuFKFeAAoDzCEu/ITQS7QGwdIhbA+4WhnQA+A9YLQdcrC
Ispc/ive03nrKTfpNOoYXsaGhdDNghMEucGJMKNchbfnkEpsub+0ahUCizQlS0Xo
L3CnY0G1PCusXQnxzGcN0QKBgA7aPIKvifR2u4jFdqfwKzTDQzjfnyc+X4/UpLV4
pJ+PNM9Lr3OEc4dooj18RZkQOFEd48NiTnGazn8VeoCix/nhuthC/NuiIRff6aMM
AL4LdcKE5n9Ee6fx+x2FMLN9zz0Kce8xCj+/0U7G7VwMYuPPhIucW2E/cCFsPzbE
vNS9AoGAZWoeCsrox+mwtreXrcB0UABK6Kctb1o2PAE5xf6SQs2CSwSfGgMGoYWj
Urqc4zd5OUhWUxE8pmKQ2ohtPSh+69AYxhRAJMmyiuWxKwsLt/4iFSc42hV35atj
0F4pTyJ6co2YpLRUXx94LBsNfGpVxLLAcRiznR+XoVGLLaEx3b8=
-----END RSA PRIVATE KEY-----`

// var tlsCert = nil

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

func handleCert(w http.ResponseWriter, req *http.Request) {
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

	serverPrivBlock, _ := pem.Decode([]byte(myPrivKey))

	// TODO(justinabrahms): PEMs may be encrpyted?
	block, _ := pem.Decode([]byte(myCert))

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

// starts an http server which listens for posts, returning a
// certificate or error.
func main() {
	// TODO(justinabrahms): Move this to TLS
	http.HandleFunc("/", index)
	http.HandleFunc("/gen-key", handleCert)

	port := 8001
	ip := "0.0.0.0"
	fmt.Printf("Listening on port %d\n", port)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", ip, port), nil); err != nil {
		log.Fatal("Could not listen for requests: ", err)
	}
}
