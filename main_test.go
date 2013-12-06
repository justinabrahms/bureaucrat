package main

import (
	"testing"
)

// Generated with a <keygen> element from Chrome.
var clientGeneratedPubkey = `MIICPDCCASYwggEgMAsGCSqGSIb3DQEBAQOCAQ8AMIIBCgKCAQEA27FuD45kjM7nJRi5pPoXi/ZP6MM6X119CkWmXA1FLfYWMuA17hBnonhXqImq6hSVZ2vKTolybpUc6w3qLGE9u/uM6HFi164cFvBJCC+BpSKooNkxTocOgtjjwv0Y/5B38B2JKJVfy4mK/QruZW9TAEJDzFj60eC7Gfy0yG5CcWBFpYqGJ8iZV62mhoPTUcqLeORwqpyhPRIxXcQUhsWTCdHWC0/w2egQw6JWUJjhUU0Vn0e88895hDIUABbZw6AGyaG/2o24uVHDYJKGXMPxcF6tYKHeNeTefoTtnz9nlGZHC3rw2TfwDoh6LatMA1jKWbSCgrwkPkSx8DxT2utqAwIDAQABFgAwCwYJKoZIhvcNAQEEA4IBAQBK7Lo78NAflw3So9e2FdAof2NTHWiUSQSHYOQSK2jo5JBHh4KlN6iktj9AYxdqe1WbPSk67jY5bdbKXDDeycuhzMuPV9yqfMS1cAELb7TLnD+fQc5ZVyZPDhaEpykrG2J+Wr59GTDlafj/2eZLO/dvsZ5uwGd09Wcv3rDVdMD1jKcf5gZZrjdziqzhDVWr1/Utpy2r+p8GzneSIJFkqe4DjoaivQLnhRnspVdq7DV860VD3Brnqje6NxELSImNy/Gvf8bZc/5FUmOMpS/ZlHcusxu6EtGCu2zzl6NdVScHYZGZa+U0ZJMDBhthLqyTFGYxuo1s0NJRJHpmF5M5RIeH`

func TestCanDecodePayload(t *testing.T) {
	_, err := StringToSPKAC(clientGeneratedPubkey)
	if err != nil {
		t.Errorf("Unable to parse SPKAC: %s", err)
	}
}
