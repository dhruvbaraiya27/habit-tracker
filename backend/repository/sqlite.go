package repository

import (
	"database/sql"
	"fmt"
	"habit-tracker/models"
	"time"

	_ "modernc.org/sqlite"
)

// HabitRepository handles database operations for habits
type HabitRepository struct {
	db *sql.DB
}

// NewHabitRepository creates a new repository with database connection
func NewHabitRepository(dbPath string) (*HabitRepository, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS habits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		streak INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return &HabitRepository{db: db}, nil
}

// Close closes the database connection
func (r *HabitRepository) Close() error {
	return r.db.Close()
}

// GetAll retrieves all habits
func (r *HabitRepository) GetAll() ([]models.Habit, error) {
	rows, err := r.db.Query("SELECT id, name, description, streak, created_at FROM habits ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var habits []models.Habit
	for rows.Next() {
		var h models.Habit
		err := rows.Scan(&h.ID, &h.Name, &h.Description, &h.Streak, &h.CreatedAt)
		if err != nil {
			return nil, err
		}
		habits = append(habits, h)
	}

	return habits, nil
}

// GetByID retrieves a single habit by ID
func (r *HabitRepository) GetByID(id int) (*models.Habit, error) {
	var h models.Habit
	err := r.db.QueryRow(
		"SELECT id, name, description, streak, created_at FROM habits WHERE id = ?",
		id,
	).Scan(&h.ID, &h.Name, &h.Description, &h.Streak, &h.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// Create adds a new habit
func (r *HabitRepository) Create(name, description string) (*models.Habit, error) {
	result, err := r.db.Exec(
		"INSERT INTO habits (name, description, streak, created_at) VALUES (?, ?, 0, ?)",
		name, description, time.Now(),
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return r.GetByID(int(id))
}

// Update modifies an existing habit
func (r *HabitRepository) Update(id int, name, description string, streak int) (*models.Habit, error) {
	_, err := r.db.Exec(
		"UPDATE habits SET name = ?, description = ?, streak = ? WHERE id = ?",
		name, description, streak, id,
	)
	if err != nil {
		return nil, err
	}

	return r.GetByID(id)
}

// Delete removes a habit
func (r *HabitRepository) Delete(id int) error {
	_, err := r.db.Exec("DELETE FROM habits WHERE id = ?", id)
	return err
}
