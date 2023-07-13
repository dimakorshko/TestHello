package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World! ")
		fmt.Fprintf(w, port)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
