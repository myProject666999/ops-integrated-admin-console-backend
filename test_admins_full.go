package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type loginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	ExpireAt string `json:"expire_at"`
}

type adminsResponse struct {
	Items []struct {
		ID        int64  `json:"id"`
		Username  string `json:"username"`
		UpdatedAt string `json:"updated_at"`
	} `json:"items"`
}

type apiError struct {
	Error string `json:"error"`
}

func main() {
	fmt.Println("=== Admins API Test Script ===")
	fmt.Println()

	dbPath := filepath.Join(".", "db", "ops_admin.db")

	fmt.Println("Step 1: Checking database...")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		fmt.Printf("Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	var adminCount int
	err = db.QueryRow(`SELECT COUNT(1) FROM admins`).Scan(&adminCount)
	if err != nil {
		fmt.Printf("Failed to count admins: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Current admin count: %d\n", adminCount)

	testUsername := "testuser_api"
	testPassword := "TestPass123!@#"

	var existingID int64
	err = db.QueryRow(`SELECT id FROM admins WHERE username = ?`, testUsername).Scan(&existingID)
	if err == nil {
		fmt.Printf("Test user '%s' already exists (id: %d)\n", testUsername, existingID)
	} else {
		fmt.Printf("Creating test user '%s'...\n", testUsername)
		hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
		if err != nil {
			fmt.Printf("Failed to hash password: %v\n", err)
			os.Exit(1)
		}
		now := time.Now().Format(time.RFC3339)
		res, err := db.Exec(`INSERT INTO admins(username,password_hash,created_at,updated_at) VALUES(?,?,?,?)`, testUsername, string(hash), now, now)
		if err != nil {
			fmt.Printf("Failed to create test user: %v\n", err)
			os.Exit(1)
		}
		id, _ := res.LastInsertId()
		fmt.Printf("Test user created with id: %d\n", id)
	}

	fmt.Println()
	fmt.Println("Step 2: Starting server...")

	cmd := exec.Command("go", "run", "main.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "ADDR=:8080")

	if err := cmd.Start(); err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Waiting for server to start...")
	time.Sleep(3 * time.Second)

	defer func() {
		fmt.Println("\nStopping server...")
		cmd.Process.Kill()
		cmd.Wait()
	}()

	baseURL := "http://localhost:8080"

	fmt.Println()
	fmt.Println("Step 3: Testing health endpoint...")
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		fmt.Printf("Health check failed: %v\n", err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("Health response: %s (status: %d)\n", string(body), resp.StatusCode)

	fmt.Println()
	fmt.Println("Step 4: Testing login...")
	loginReq := map[string]string{
		"username": testUsername,
		"password": testPassword,
	}
	loginBody, _ := json.Marshal(loginReq)
	resp, err = http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		fmt.Printf("Login request failed: %v\n", err)
		os.Exit(1)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("Login response: %s (status: %d)\n", string(body), resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Login failed!")
		os.Exit(1)
	}

	var loginResp loginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		fmt.Printf("Failed to parse login response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Login successful! Token: %s...\n", loginResp.Token[:20])

	fmt.Println()
	fmt.Println("Step 5: Testing /api/admins endpoint...")
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/admins", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Admins request failed: %v\n", err)
		os.Exit(1)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("Admins response: %s (status: %d)\n", string(body), resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Admins API failed!")
		os.Exit(1)
	}

	var adminsResp adminsResponse
	if err := json.Unmarshal(body, &adminsResp); err != nil {
		fmt.Printf("Failed to parse admins response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("=== Admins List ===")
	for _, admin := range adminsResp.Items {
		fmt.Printf("ID: %d, Username: %s, UpdatedAt: %s\n", admin.ID, admin.Username, admin.UpdatedAt)
	}

	fmt.Println()
	fmt.Println("=== All tests passed! ===")
}
