package main

import "net/http"

func main() {

	http.HandleFunc("/attestation/options", AttestationOptions)

	http.ListenAndServe(":8080", nil)
}
