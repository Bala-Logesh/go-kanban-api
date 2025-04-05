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
	ID      string `json:"id,omitempty"`
}

func main() {
	log.Println("Starting server")
	router := mux.NewRouter()

	port := 3000
	url := fmt.Sprintf("127.0.0.1:%d", port)

	log.Println("Setting up routes")
	router.HandleFunc("/", handleRoot).Methods("GET")
	router.HandleFunc("/register", handleRegister).Methods("POST")
	router.HandleFunc("/login", handleLogin).Methods("POST")
	router.HandleFunc("/projects", handleGetProjects).Methods("GET")
	router.HandleFunc("/projects/{id}", handleGetProject).Methods("GET")
	router.HandleFunc("/projects", handleCreateProject).Methods("POST")
	router.HandleFunc("/projects/{id}", handleUpdateProject).Methods("PUT")
	router.HandleFunc("/projects/{id}", handleDeleteProject).Methods("DELETE")

	log.Printf("Server running on %v\n", url)
	log.Fatal(http.ListenAndServe(url, router))
}

// Root route
func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from server"})
}

// Register User
func handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from register"})
}

// Login User
func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from login"})
}

// Create Project
func handleCreateProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from create project"})
}

// Update Project
func handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	id := getIDFromRoute(r)
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from update project", ID: id})
}

// Get Projects
func handleGetProjects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from get projects"})
}

// Get Project
func handleGetProject(w http.ResponseWriter, r *http.Request) {
	id := getIDFromRoute(r)
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from get project", ID: id})
}

// Delete Project
func handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	id := getIDFromRoute(r)
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from delete project", ID: id})
}

func getIDFromRoute(r *http.Request) string {
	idStr := mux.Vars(r)["id"]

	return idStr
}
