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
	"github.com/lib/pq"
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

type Project struct {
	ID              string   `json:"id,omitempty"`
	User            string   `json:"user,omitempty"`
	Name            string   `json:"name,omitempty"`
	RepoURL         string   `json:"repo_url,omitempty"`
	SiteURL         string   `json:"site_url,omitempty"`
	Description     string   `json:"description,omitempty"`
	Dependencies    []string `json:"dependencies,omitempty"`
	DevDependencies []string `json:"dev_dependencies,omitempty"`
	Status          string   `json:"status,omitempty"`
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

	projectSchema, loadErr := loadSchema("schemas/project.json")

	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v\n", loadErr)
	}

	app := &App{DB: DB, JWTKey: []byte(JWTKey), claimsKey: "claims"}

	log.Println("Starting server")
	router := mux.NewRouter()

	port := 3000
	url := fmt.Sprintf("127.0.0.1:%d", port)

	log.Println("Setting up routes")
	setupRoutes(router, app, userSchema, projectSchema)

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

// Create Project to handle project creation
func (app *App) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var project Project

	err := json.NewDecoder(r.Body).Decode(&project)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	claims := r.Context().Value(app.claimsKey).(*Claims)
	userID := claims.ID

	var id string
	err = app.DB.QueryRow("INSERT INTO \"projects\" (\"user\", name, repo_url, site_url, description, dependencies, dev_dependencies, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id", userID, project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status).Scan(&id)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating project")
		return
	}

	project.ID = id
	project.User = userID

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// Update Project to handle editing project
func (app *App) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	var project Project

	err := json.NewDecoder(r.Body).Decode(&project)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	id := getIDFromRoute(r)

	claims := r.Context().Value(app.claimsKey).(*Claims)
	userID := claims.ID

	var storedUserID string
	err = app.DB.QueryRow("SELECT \"user\" FROM projects WHERE id=$1", id).Scan(&storedUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Project not found")
			return
		}

		respondWithError(w, http.StatusInternalServerError, "Error fetching project")
		return
	}

	if storedUserID != userID {
		respondWithError(w, http.StatusForbidden, "You do not have permissions to update this project")
		return
	}

	_, err = app.DB.Exec("UPDATE projects SET name=$1, repo_url=$2, site_url=$3, description=$4, dependencies=$5, dev_dependencies=$6, status=$7 WHERE id=$8 AND \"user\"=$9", project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status, id, userID)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error updating project")
		return
	}

	project.ID = id
	project.User = userID

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// Get Projects to handle fetching projects
func (app *App) handleGetProjects(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(app.claimsKey).(*Claims)
	userID := claims.ID

	rows, err := app.DB.Query("SELECT id, \"user\", name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE \"user\"=$1", userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error fetching projects")
		return
	}

	defer rows.Close()

	var projects []Project

	for rows.Next() {
		var project Project
		var dependencies, devDependencies []string

		err = rows.Scan(&project.ID, &project.User, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)

		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Error scanning project")
			return
		}

		project.Dependencies = dependencies
		project.DevDependencies = devDependencies
		projects = append(projects, project)
	}

	err = rows.Err()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error fetching projects")
		return
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

// Get Project to handle fetching project with id
func (app *App) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id := getIDFromRoute(r)

	claims := r.Context().Value(app.claimsKey).(*Claims)
	userID := claims.ID

	var project Project
	var dependencies, devDependencies []string

	err := app.DB.QueryRow("SELECT id, \"user\", name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE \"user\"=$1 and ID=$2", userID, id).Scan(&project.ID, &project.User, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Project not found")
			return
		}

		respondWithError(w, http.StatusInternalServerError, "Error fetching project")
		return
	}

	project.Dependencies = dependencies
	project.DevDependencies = devDependencies

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// Delete Project to handle deleting project with id
func (app *App) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	id := getIDFromRoute(r)

	claims := r.Context().Value(app.claimsKey).(*Claims)
	userID := claims.ID

	var storedUserID string
	err := app.DB.QueryRow("SELECT \"user\" FROM projects WHERE id=$1", id).Scan(&storedUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Project not found")
			return
		}

		respondWithError(w, http.StatusInternalServerError, "Error fetching project")
		return
	}

	if storedUserID != userID {
		respondWithError(w, http.StatusForbidden, "You do not have permissions to delete this project")
		return
	}

	_, err = app.DB.Exec("DELETE FROM projects WHERE id=$1 AND \"user\"=$2", id, userID)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error deleting project")
		return
	}

	w.WriteHeader(http.StatusNoContent)
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

func setupRoutes(router *mux.Router, app *App, userSchema, projectSchema string) {
	router.Handle("/", alice.New(loggingMiddleware).ThenFunc(handleRoot)).Methods("GET")

	// Middleware chain and routes for user auth
	userChain := alice.New(loggingMiddleware, validateMiddleware(userSchema))
	router.Handle("/register", userChain.ThenFunc(app.handleRegister)).Methods("POST")
	router.Handle("/login", userChain.ThenFunc(app.handleLogin)).Methods("POST")

	// Middleware chain and routes for projects that do not require body
	projectChain := alice.New(loggingMiddleware, app.jwtMiddleware)
	router.Handle("/projects", projectChain.ThenFunc(app.handleGetProjects)).Methods("GET")
	router.Handle("/projects/{id}", projectChain.ThenFunc(app.handleGetProject)).Methods("GET")
	router.Handle("/projects/{id}", projectChain.ThenFunc(app.handleDeleteProject)).Methods("DELETE")

	// Middleware chain and routes for projects that do not require body
	projectChainWithValidation := projectChain.Append(validateMiddleware(projectSchema))
	router.Handle("/projects", projectChainWithValidation.ThenFunc(app.handleCreateProject)).Methods("POST")
	router.Handle("/projects/{id}", projectChainWithValidation.ThenFunc(app.handleUpdateProject)).Methods("PUT")
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

// This function is similar to logging middleware but it is a wrapper that returns the logging middleware like function itself
// The return statement on the line 2 of the function actually return ths logging middleware like function
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
