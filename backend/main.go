package main

import (
	"database/sql"
	"fmt"
	"habit-tracker/handlers"
	"habit-tracker/middleware"
	"habit-tracker/repository"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create data directory if it doesn't exist
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatal("Failed to create data directory:", err)
	}

	dbPath := fmt.Sprintf("%s/habits.db", dataDir)
	logger.Info("using database", "path", dbPath)

	// Initialize database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// Initialize repositories
	habitRepo, err := repository.NewHabitRepository(dbPath)
	if err != nil {
		log.Fatal("Failed to initialize habit repository:", err)
	}
	defer habitRepo.Close()

	userRepo, err := repository.NewUserRepository(db)
	if err != nil {
		log.Fatal("Failed to initialize user repository:", err)
	}

	logger.Info("database initialized successfully")

	// Initialize handlers
	habitHandler := handlers.NewHabitHandler(habitRepo, logger)
	authHandler := handlers.NewAuthHandler(userRepo, logger)

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.Logger(logger))

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // Allow all origins for Docker
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Public routes
	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
	})

	// Protected routes
	r.Route("/api/habits", func(r chi.Router) {
		r.Use(middleware.JWTAuth(logger))

		r.Get("/", habitHandler.GetAllHabits)
		r.Post("/", habitHandler.CreateHabit)
		r.Get("/{id}", habitHandler.GetHabit)
		r.Put("/{id}", habitHandler.UpdateHabit)
		r.Delete("/{id}", habitHandler.DeleteHabit)
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logger.Info("server starting", "port", port)
	fmt.Printf("🚀 Server running at http://localhost:%s\n", port)
	fmt.Println("\n📋 Public API endpoints:")
	fmt.Println("   POST   http://localhost:" + port + "/api/auth/register")
	fmt.Println("   POST   http://localhost:" + port + "/api/auth/login")
	fmt.Println("   GET    http://localhost:" + port + "/health")
	fmt.Println("\n🔒 Protected API endpoints (require JWT token):")
	fmt.Println("   GET    http://localhost:" + port + "/api/habits")
	fmt.Println("   POST   http://localhost:" + port + "/api/habits")
	fmt.Println("   GET    http://localhost:" + port + "/api/habits/{id}")
	fmt.Println("   PUT    http://localhost:" + port + "/api/habits/{id}")
	fmt.Println("   DELETE http://localhost:" + port + "/api/habits/{id}")

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
