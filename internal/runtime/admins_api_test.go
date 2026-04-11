package runtime

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func setupTestDB(t *testing.T) *sql.DB {
	dbDir := "./test_db"
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("创建测试数据库目录失败: %v", err)
	}

	dbPath := filepath.Join(dbDir, "test_ops_admin.db")
	_ = os.Remove(dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	cfg := appConfig{
		CredentialKey: "test-secret-key",
	}
	if err := initDB(db, cfg); err != nil {
		t.Fatalf("初始化测试数据库失败: %v", err)
	}

	return db
}

func insertTestAdmin(t *testing.T, db *sql.DB, username, password string) int64 {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("密码加密失败: %v", err)
	}

	now := nowStr()
	res, err := db.Exec(
		`INSERT INTO admins(username,password_hash,created_at,updated_at) VALUES(?,?,?,?)`,
		username, string(hash), now, now,
	)
	if err != nil {
		t.Fatalf("插入测试用户失败: %v", err)
	}

	userID, _ := res.LastInsertId()
	return userID
}

func loginTestUser(t *testing.T, srv *server, username, password string) string {
	loginBody := map[string]string{
		"username": username,
		"password": password,
	}
	body, _ := json.Marshal(loginBody)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.route(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("登录失败，状态码: %d, 响应: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("解析登录响应失败: %v", err)
	}

	token, ok := resp["token"].(string)
	if !ok {
		t.Fatalf("登录响应中没有token")
	}

	return token
}

func TestAdminsListAPI(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer os.RemoveAll("./test_db")

	insertTestAdmin(t, db, "admin1", "Admin123456")
	insertTestAdmin(t, db, "admin2", "Admin123456")
	insertTestAdmin(t, db, "admin3", "Admin123456")

	srv := &server{
		db:                 db,
		tokenTTL:           24 * time.Hour,
		cfg:                appConfig{},
		jobs:               make(map[string]*asyncOperateJob),
		projectSessions:    newProjectSessionManager(),
		browserCloseStates: make(map[string]*browserCloseState),
	}

	token := loginTestUser(t, srv, "admin1", "Admin123456")

	t.Run("无认证访问管理员列表", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/admins", nil)
		w := httptest.NewRecorder()
		srv.route(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("期望状态码 %d，实际 %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("正常访问管理员列表", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/admins", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.route(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d，实际 %d, 响应: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("解析响应失败: %v", err)
		}

		total, ok := resp["total"].(float64)
		if !ok {
			t.Error("响应中没有total字段")
		}
		if int(total) != 3 {
			t.Errorf("期望管理员数量 3，实际 %d", int(total))
		}

		items, ok := resp["items"].([]interface{})
		if !ok {
			t.Error("响应中没有items字段")
		}

		if len(items) != 3 {
			t.Errorf("期望管理员列表长度 3，实际 %d", len(items))
		}

		for _, item := range items {
			admin, ok := item.(map[string]interface{})
			if !ok {
				t.Error("管理员数据格式错误")
				continue
			}

			if _, ok := admin["id"]; !ok {
				t.Error("管理员数据缺少id字段")
			}
			if _, ok := admin["username"]; !ok {
				t.Error("管理员数据缺少username字段")
			}
			if _, ok := admin["updated_at"]; !ok {
				t.Error("管理员数据缺少updated_at字段")
			}
			if _, ok := admin["password_hash"]; ok {
				t.Error("管理员数据不应该包含password_hash字段")
			}
		}
	})

	t.Run("测试数据密码加密", func(t *testing.T) {
		var hash string
		err := db.QueryRow(`SELECT password_hash FROM admins WHERE username=?`, "admin1").Scan(&hash)
		if err != nil {
			t.Fatalf("查询密码哈希失败: %v", err)
		}

		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("Admin123456"))
		if err != nil {
			t.Error("密码验证失败，bcrypt加密不正确")
		}
	})
}
