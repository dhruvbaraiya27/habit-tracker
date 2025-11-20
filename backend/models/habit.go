package models

import "time"

// Habit represents a habit that a user wants to track
type Habit struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Streak      int       `json:"streak"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateHabitRequest is the payload for creating a new habit
type CreateHabitRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// UpdateHabitRequest is the payload for updating a habit
type UpdateHabitRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Streak      int    `json:"streak"`
}
