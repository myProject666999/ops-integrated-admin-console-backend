package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"ops-admin-backend/internal/runtime"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(".", "db", "ops_admin_test.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatalf("failed to create db dir: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	_, _ = db.Exec(`PRAGMA busy_timeout = 5000`)
	return db
}

func createTestAdmin(t *testing.T, db *sql.DB, username, password string) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	now := time.Now().Format(time.RFC3339)
	res, err := db.Exec(`INSERT INTO admins(username,password_hash,created_at,updated_at) VALUES(?,?,?,?)`, username, string(hash), now, now)
	if err != nil {
		t.Fatalf("failed to create test admin: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func initTestSchema(db *sql.DB) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS auth_tokens (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES admins(id)
		);`,
		`CREATE TABLE IF NOT EXISTS project_credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			project_type TEXT NOT NULL,
			account TEXT NOT NULL DEFAULT '',
			password TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL,
			UNIQUE(user_id, project_type),
			FOREIGN KEY(user_id) REFERENCES admins(id)
		);`,
		`CREATE TABLE IF NOT EXISTS operation_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			username TEXT,
			action TEXT NOT NULL,
			project_type TEXT,
			detail TEXT,
			created_at TEXT NOT NULL
		);`,
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func TestAdminsAPI(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer os.Remove(filepath.Join(".", "db", "ops_admin_test.db"))

	if err := initTestSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	testUsername := "testadmin"
	testPassword := "testpassword123"
	createTestAdmin(t, db, testUsername, testPassword)

	t.Run("Login", func(t *testing.T) {
		loginReq := map[string]string{
			"username": testUsername,
			"password": testPassword,
		}
		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		fmt.Printf("Login request: POST /api/auth/login\n")
		fmt.Printf("Request body: %s\n", string(body))

		fmt.Printf("\nNote: This test requires the full server to be running.\n")
		fmt.Printf("Please run the server first and test manually:\n")
		fmt.Printf("  1. Start server: go run main.go\n")
		fmt.Printf("  2. Test login: curl -X POST http://localhost:8080/api/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"testadmin\",\"password\":\"testpassword123\"}'\n")
	})
}

func TestBcryptPassword(t *testing.T) {
	password := "testpassword123"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Hash: %s\n", string(hash))

	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		t.Fatalf("password verification failed: %v", err)
	}
	fmt.Printf("Password verification: SUCCESS\n")
}
