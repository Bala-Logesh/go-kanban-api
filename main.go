package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type RouteResponse struct {
	Message string `json:"message"`
}

func main() {
	router := mux.NewRouter()
	port := 3000
	url := fmt.Sprintf("127.0.0.1:%d", port)

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-type", "application/json")
		json.NewEncoder(w).Encode(RouteResponse{Message: "Hello World"})
	}).Methods("GET")

	fmt.Printf("Server running on %v\n", url)
	log.Fatal(http.ListenAndServe(url, router))
}
