package handlers

import (
	"encoding/json"
	"habit-tracker/models"
	"habit-tracker/repository"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// HabitHandler handles all habit-related HTTP requests
type HabitHandler struct {
	repo   *repository.HabitRepository
	logger *slog.Logger
}

// NewHabitHandler creates a new handler
func NewHabitHandler(repo *repository.HabitRepository, logger *slog.Logger) *HabitHandler {
	return &HabitHandler{
		repo:   repo,
		logger: logger,
	}
}

// GetAllHabits handles GET /api/habits
func (h *HabitHandler) GetAllHabits(w http.ResponseWriter, r *http.Request) {
	h.logger.Info("getting all habits")

	habits, err := h.repo.GetAll()
	if err != nil {
		h.logger.Error("failed to get habits", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return empty array instead of null if no habits
	if habits == nil {
		habits = []models.Habit{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(habits)
}

// GetHabit handles GET /api/habits/{id}
func (h *HabitHandler) GetHabit(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logger.Warn("invalid habit ID", "id", idStr)
		http.Error(w, "Invalid habit ID", http.StatusBadRequest)
		return
	}

	h.logger.Info("getting habit", "id", id)

	habit, err := h.repo.GetByID(id)
	if err != nil {
		h.logger.Error("failed to get habit", "error", err, "id", id)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if habit == nil {
		http.Error(w, "Habit not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(habit)
}

// CreateHabit handles POST /api/habits
func (h *HabitHandler) CreateHabit(w http.ResponseWriter, r *http.Request) {
	var req models.CreateHabitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validation
	if req.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	h.logger.Info("creating habit", "name", req.Name)

	habit, err := h.repo.Create(req.Name, req.Description)
	if err != nil {
		h.logger.Error("failed to create habit", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(habit)
}

// UpdateHabit handles PUT /api/habits/{id}
func (h *HabitHandler) UpdateHabit(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logger.Warn("invalid habit ID", "id", idStr)
		http.Error(w, "Invalid habit ID", http.StatusBadRequest)
		return
	}

	var req models.UpdateHabitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("invalid request body", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validation
	if req.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	h.logger.Info("updating habit", "id", id)

	// Check if habit exists
	existing, err := h.repo.GetByID(id)
	if err != nil {
		h.logger.Error("failed to get habit", "error", err, "id", id)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "Habit not found", http.StatusNotFound)
		return
	}

	habit, err := h.repo.Update(id, req.Name, req.Description, req.Streak)
	if err != nil {
		h.logger.Error("failed to update habit", "error", err, "id", id)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(habit)
}

// DeleteHabit handles DELETE /api/habits/{id}
func (h *HabitHandler) DeleteHabit(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.logger.Warn("invalid habit ID", "id", idStr)
		http.Error(w, "Invalid habit ID", http.StatusBadRequest)
		return
	}

	h.logger.Info("deleting habit", "id", id)

	// Check if habit exists
	existing, err := h.repo.GetByID(id)
	if err != nil {
		h.logger.Error("failed to get habit", "error", err, "id", id)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "Habit not found", http.StatusNotFound)
		return
	}

	if err := h.repo.Delete(id); err != nil {
		h.logger.Error("failed to delete habit", "error", err, "id", id)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
