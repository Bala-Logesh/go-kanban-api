package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	_ "github.com/lib/pq"
)

type App struct {
	DB *sql.DB
}

type RouteResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	log.Println("Connecting to database")
	connStr := os.Getenv("PSQL_URL")
	if len(connStr) == 0 {
		log.Fatalf("PSQL_URL environment variable is not set")
	}

	DB, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatal(err)
	}

	log.Println("Creating tables")
	createUsersTable(DB)
	createProjectsTable(DB)

	defer DB.Close()

	// app := &App{DB: DB}

	log.Println("Starting server")
	router := mux.NewRouter()

	port := 3000
	url := fmt.Sprintf("127.0.0.1:%d", port)

	log.Println("Setting up routes")
	router.Handle("/", alice.New(loggingMiddleware).ThenFunc(handleRoot)).Methods("GET")

	router.Handle("/register", alice.New(loggingMiddleware).ThenFunc(handleRegister)).Methods("POST")

	router.Handle("/login", alice.New(loggingMiddleware).ThenFunc(handleLogin)).Methods("POST")

	router.Handle("/projects", alice.New(loggingMiddleware).ThenFunc(handleGetProjects)).Methods("GET")

	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(handleGetProject)).Methods("GET")

	router.Handle("/projects", alice.New(loggingMiddleware).ThenFunc(handleCreateProject)).Methods("POST")

	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(handleUpdateProject)).Methods("PUT")

	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(handleDeleteProject)).Methods("DELETE")

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

// Helpers
func getIDFromRoute(r *http.Request) string {
	idStr := mux.Vars(r)["id"]

	return idStr
}

func createProjectsTable(DB *sql.DB) {
	query := `CREATE TABLE IF NOT EXISTS projects (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL,
		repo_url TEXT,
		site_url TEXT,
		description TEXT,
		dependencies TEXT[],
		dev_dependencies TEXT[],
		status TEXT NOT NULL CHECK (status IN ('backlog', 'developing', 'done')),
		"user" TEXT REFERENCES users(username) ON DELETE NO ACTION
	)`

	_, err := DB.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
}


func createUsersTable(DB *sql.DB) {
	query := `CREATE TABLE IF NOT EXISTS users (
		username TEXT NOT NULL UNIQUE, 
		password TEXT NOT NULL
	)`

	_, err := DB.Exec(query)
	
	if err != nil {
		log.Fatal(err)
	}
}

// Middlewares
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)

		next.ServeHTTP(w, r)
	})
}
