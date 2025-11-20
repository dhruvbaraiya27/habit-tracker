package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"habit-tracker/handlers"
	"habit-tracker/middleware"
	"habit-tracker/models"
	"habit-tracker/repository"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("your-secret-key-change-this-in-production")

// setupTestDB creates a fresh test database for each test
func setupTestDB(t *testing.T) (*sql.DB, *repository.HabitRepository, *repository.UserRepository) {
	// Use in-memory SQLite database for tests
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	habitRepo, err := repository.NewHabitRepository(":memory:")
	if err != nil {
		t.Fatalf("Failed to create habit repository: %v", err)
	}

	userRepo, err := repository.NewUserRepository(db)
	if err != nil {
		t.Fatalf("Failed to create user repository: %v", err)
	}

	return db, habitRepo, userRepo
}

// setupTestRouter creates a router with test handlers
func setupTestRouter(habitRepo *repository.HabitRepository, userRepo *repository.UserRepository) *chi.Mux {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Only log errors in tests
	}))

	habitHandler := handlers.NewHabitHandler(habitRepo, logger)
	authHandler := handlers.NewAuthHandler(userRepo, logger)

	r := chi.NewRouter()

	// Public auth routes
	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
	})

	// Protected habit routes
	r.Route("/api/habits", func(r chi.Router) {
		r.Use(middleware.JWTAuth(logger))

		r.Get("/", habitHandler.GetAllHabits)
		r.Post("/", habitHandler.CreateHabit)
		r.Get("/{id}", habitHandler.GetHabit)
		r.Put("/{id}", habitHandler.UpdateHabit)
		r.Delete("/{id}", habitHandler.DeleteHabit)
	})

	return r
}

// generateTestToken creates a valid JWT token for testing
func generateTestToken(username string, userID int) string {
	claims := &handlers.Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)
	return tokenString
}

// ==================== AUTHENTICATION TESTS ====================

// Test 1: Register new user successfully
func TestRegister_Success(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	reqBody := models.LoginRequest{
		Username: "testuser",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	var response map[string]string
	json.NewDecoder(w.Body).Decode(&response)

	if response["username"] != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", response["username"])
	}

	if response["message"] != "User created successfully" {
		t.Errorf("Unexpected message: %s", response["message"])
	}
}

// Test 2: Register with missing username
func TestRegister_MissingUsername(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	reqBody := models.LoginRequest{
		Username: "",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// Test 3: Register with missing password
func TestRegister_MissingPassword(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	reqBody := models.LoginRequest{
		Username: "testuser",
		Password: "",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// Test 4: Register duplicate username
func TestRegister_DuplicateUsername(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	// Create first user
	userRepo.CreateUser("testuser", "password123")

	// Try to create duplicate
	reqBody := models.LoginRequest{
		Username: "testuser",
		Password: "password456",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status 409, got %d", w.Code)
	}
}

// Test 5: Login successfully
func TestLogin_Success(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	// Create user first
	userRepo.CreateUser("testuser", "password123")

	// Login
	reqBody := models.LoginRequest{
		Username: "testuser",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response models.LoginResponse
	json.NewDecoder(w.Body).Decode(&response)

	if response.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", response.Username)
	}

	if response.Token == "" {
		t.Error("Expected token to be present")
	}
}

// Test 6: Login with wrong password
func TestLogin_WrongPassword(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	// Create user
	userRepo.CreateUser("testuser", "password123")

	// Login with wrong password
	reqBody := models.LoginRequest{
		Username: "testuser",
		Password: "wrongpassword",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// Test 7: Login with non-existent user
func TestLogin_NonExistentUser(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	reqBody := models.LoginRequest{
		Username: "nonexistent",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// Test 8: Login with missing credentials
func TestLogin_MissingCredentials(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	reqBody := models.LoginRequest{
		Username: "",
		Password: "",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// ==================== PROTECTED ROUTES TESTS ====================

// Test 9: Access protected route without token
func TestProtectedRoute_NoToken(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	req := httptest.NewRequest("GET", "/api/habits", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// Test 10: Access protected route with invalid token
func TestProtectedRoute_InvalidToken(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	req := httptest.NewRequest("GET", "/api/habits", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-here")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// Test 11: Access protected route with expired token
func TestProtectedRoute_ExpiredToken(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	// Create expired token
	claims := &handlers.Claims{
		Username: "testuser",
		UserID:   1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)

	req := httptest.NewRequest("GET", "/api/habits", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// ==================== HABIT CRUD TESTS WITH AUTH ====================

// Test 12: Create habit with valid token
func TestCreateHabit_WithAuth_Success(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	reqBody := models.CreateHabitRequest{
		Name:        "Morning Run",
		Description: "Run 5km every morning",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/habits", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	var habit models.Habit
	json.NewDecoder(w.Body).Decode(&habit)

	if habit.Name != reqBody.Name {
		t.Errorf("Expected name '%s', got '%s'", reqBody.Name, habit.Name)
	}
}

// Test 13: Create habit without auth token
func TestCreateHabit_NoAuth(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	reqBody := models.CreateHabitRequest{
		Name:        "Morning Run",
		Description: "Run 5km every morning",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/habits", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// Test 14: Create habit with missing name
func TestCreateHabit_WithAuth_MissingName(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	reqBody := models.CreateHabitRequest{
		Name:        "",
		Description: "Some description",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/habits", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// Test 15: Get all habits with auth
func TestGetAllHabits_WithAuth_Success(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	// Create some habits
	habitRepo.Create("Habit 1", "Description 1")
	habitRepo.Create("Habit 2", "Description 2")

	req := httptest.NewRequest("GET", "/api/habits", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var habits []models.Habit
	json.NewDecoder(w.Body).Decode(&habits)

	if len(habits) != 2 {
		t.Errorf("Expected 2 habits, got %d", len(habits))
	}
}

// Test 16: Get all habits empty with auth
func TestGetAllHabits_WithAuth_Empty(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	req := httptest.NewRequest("GET", "/api/habits", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var habits []models.Habit
	json.NewDecoder(w.Body).Decode(&habits)

	if habits == nil {
		t.Error("Expected empty array, got nil")
	}

	if len(habits) != 0 {
		t.Errorf("Expected 0 habits, got %d", len(habits))
	}
}

// Test 17: Get single habit with auth
func TestGetHabit_WithAuth_Success(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	// Create a habit
	habitRepo.Create("Test Habit", "Test Description")

	req := httptest.NewRequest("GET", "/api/habits/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var habit models.Habit
	json.NewDecoder(w.Body).Decode(&habit)

	if habit.Name != "Test Habit" {
		t.Errorf("Expected name 'Test Habit', got '%s'", habit.Name)
	}
}

// Test 18: Get non-existent habit with auth
func TestGetHabit_WithAuth_NotFound(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	req := httptest.NewRequest("GET", "/api/habits/999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "999")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// Test 19: Get habit with invalid ID
func TestGetHabit_WithAuth_InvalidID(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	req := httptest.NewRequest("GET", "/api/habits/abc", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "abc")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// Test 20: Update habit with auth
func TestUpdateHabit_WithAuth_Success(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	// Create a habit
	habitRepo.Create("Old Name", "Old Description")

	updateReq := models.UpdateHabitRequest{
		Name:        "New Name",
		Description: "New Description",
		Streak:      5,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/habits/1", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var habit models.Habit
	json.NewDecoder(w.Body).Decode(&habit)

	if habit.Name != "New Name" {
		t.Errorf("Expected name 'New Name', got '%s'", habit.Name)
	}

	if habit.Streak != 5 {
		t.Errorf("Expected streak 5, got %d", habit.Streak)
	}
}

// Test 21: Update non-existent habit with auth
func TestUpdateHabit_WithAuth_NotFound(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	updateReq := models.UpdateHabitRequest{
		Name:        "New Name",
		Description: "New Description",
		Streak:      5,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/habits/999", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "999")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// Test 22: Update habit without auth
func TestUpdateHabit_NoAuth(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	updateReq := models.UpdateHabitRequest{
		Name:        "New Name",
		Description: "New Description",
		Streak:      5,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/habits/1", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// Test 23: Delete habit with auth
func TestDeleteHabit_WithAuth_Success(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	// Create a habit
	habitRepo.Create("To Delete", "Will be deleted")

	req := httptest.NewRequest("DELETE", "/api/habits/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	// Verify deletion
	habit, _ := habitRepo.GetByID(1)
	if habit != nil {
		t.Error("Habit should be deleted but still exists")
	}
}

// Test 24: Delete non-existent habit with auth
func TestDeleteHabit_WithAuth_NotFound(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	token := generateTestToken("testuser", 1)

	req := httptest.NewRequest("DELETE", "/api/habits/999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "999")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// Test 25: Delete habit without auth
func TestDeleteHabit_NoAuth(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	req := httptest.NewRequest("DELETE", "/api/habits/1", nil)
	w := httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// ==================== INTEGRATION TESTS ====================

// Test 26: Full user workflow - Register, Login, Create Habit, Get Habit
func TestIntegration_FullWorkflow(t *testing.T) {
	db, habitRepo, userRepo := setupTestDB(t)
	defer db.Close()
	defer habitRepo.Close()
	router := setupTestRouter(habitRepo, userRepo)

	// Step 1: Register
	registerReq := models.LoginRequest{
		Username: "integrationuser",
		Password: "testpass123",
	}
	body, _ := json.Marshal(registerReq)
	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Registration failed: %d", w.Code)
	}

	// Step 2: Login
	loginReq := models.LoginRequest{
		Username: "integrationuser",
		Password: "testpass123",
	}
	body, _ = json.Marshal(loginReq)
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Login failed: %d", w.Code)
	}

	var loginResp models.LoginResponse
	json.NewDecoder(w.Body).Decode(&loginResp)
	token := loginResp.Token

	// Step 3: Create a habit with token
	habitReq := models.CreateHabitRequest{
		Name:        "Integration Test Habit",
		Description: "Testing full workflow",
	}
	body, _ = json.Marshal(habitReq)
	req = httptest.NewRequest("POST", "/api/habits", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Create habit failed: %d", w.Code)
	}

	var habit models.Habit
	json.NewDecoder(w.Body).Decode(&habit)

	// Step 4: Get the habit
	req = httptest.NewRequest("GET", "/api/habits/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Get habit failed: %d", w.Code)
	}

	var retrievedHabit models.Habit
	json.NewDecoder(w.Body).Decode(&retrievedHabit)

	if retrievedHabit.Name != "Integration Test Habit" {
		t.Errorf("Expected habit name 'Integration Test Habit', got '%s'", retrievedHabit.Name)
	}
}
