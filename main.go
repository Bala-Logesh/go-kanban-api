package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	_ "github.com/lib/pq"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB        *sql.DB
	JWTKey    []byte
	claimsKey contextKey
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type contextKey string

type Claims struct {
	Username string `json:"username"`
	ID       string `json:"id"`
	jwt.RegisteredClaims
}

type UserResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

type ErrorResponse struct {
	Message string `json:"message"`
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

	JWTKey := os.Getenv("JWT_SECRET")
	if len(JWTKey) == 0 {
		log.Fatalf("JWTKey environment variable is not set")
	}

	var loadErr error
	userSchema, loadErr := loadSchema("schemas/user.json")

	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v\n", loadErr)
	}

	app := &App{DB: DB, JWTKey: []byte(JWTKey), claimsKey: "claims"}

	log.Println("Starting server")
	router := mux.NewRouter()

	port := 3000
	url := fmt.Sprintf("127.0.0.1:%d", port)

	log.Println("Setting up routes")

	// Middleware chain and routes for user auth
	userChain := alice.New(loggingMiddleware, validateMiddleware(userSchema))

	router.Handle("/", alice.New(loggingMiddleware).ThenFunc(handleRoot)).Methods("GET")

	router.Handle("/register", userChain.ThenFunc(app.handleRegister)).Methods("POST")

	router.Handle("/login", userChain.ThenFunc(app.handleLogin)).Methods("POST")

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

// Register function to handle user registration
func (app *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Error hashing password")
		return
	}

	var id string
	err = app.DB.QueryRow("INSERT INTO \"users\" (username, password) VALUES ($1, $2) RETURNING id", creds.Username, string(hashedPwd)).Scan(&id)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Error creating user")
		return
	}

	tokenString, err := app.generateToken(creds.Username, id)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{ID: id, Username: creds.Username, Token: tokenString})
}

// Login function to handle user login
func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var storedCreds Credentials
	var id string
	err = app.DB.QueryRow("SELECT id, username, password FROM \"users\" WHERE username=$1", creds.Username).Scan(&id, &storedCreds.Username, &storedCreds.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Invalid request payload")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password))

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	tokenString, err := app.generateToken(creds.Username, id)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{ID: id, Username: creds.Username, Token: tokenString})
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
		"user" INTEGER REFERENCES users(id) ON DELETE NO ACTION
	)`

	_, err := DB.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
}

func createUsersTable(DB *sql.DB) {
	query := `CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT NOT NULL UNIQUE, 
		password TEXT NOT NULL
	)`

	_, err := DB.Exec(query)

	if err != nil {
		log.Fatal(err)
	}
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

func (app *App) generateToken(username, id string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Username: username,
		ID:       id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(app.JWTKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Loads JSON schema from a file
func loadSchema(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)

	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Middlewares
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)

		next.ServeHTTP(w, r)
	})
}

func (app *App) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, "No token provided")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				respondWithError(w, http.StatusUnauthorized, "Invalid token signature")
				return
			}

			respondWithError(w, http.StatusBadRequest, "Invalid token")
			return
		}

		if !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), app.claimsKey, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateMiddleware(schema string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]interface{}

			bodyBytes, err := io.ReadAll(r.Body)

			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
				return
			}

			err = json.Unmarshal(bodyBytes, &body)

			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
				return
			}

			schemaLoader := gojsonschema.NewStringLoader(schema)
			documentLoader := gojsonschema.NewGoLoader(body)

			result, err := gojsonschema.Validate(schemaLoader, documentLoader)

			if err != nil {
				respondWithError(w, http.StatusInternalServerError, "Error validating JSON")
				return
			}

			if !result.Valid() {
				var errs []string

				for _, err := range result.Errors() {
					errs = append(errs, err.String())
				}

				respondWithError(w, http.StatusInternalServerError, strings.Join(errs, ", "))
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
		})
	}
}
