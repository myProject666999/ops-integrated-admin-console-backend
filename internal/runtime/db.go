package runtime

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func initDB(db *sql.DB, cfg appConfig) error {
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
		`CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS menus (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			path TEXT NOT NULL,
			icon TEXT DEFAULT '',
			parent_id INTEGER DEFAULT 0,
			sort_order INTEGER DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS role_menu (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role_id INTEGER NOT NULL,
			menu_id INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(role_id, menu_id),
			FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
			FOREIGN KEY(menu_id) REFERENCES menus(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS user_role (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			role_id INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(user_id, role_id),
			FOREIGN KEY(user_id) REFERENCES admins(id) ON DELETE CASCADE,
			FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
		);`,
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	var err error

	if err = migrateProjectCredentialsSchema(db); err != nil {
		return err
	}
	if err = migrateAuthTokensSchema(db); err != nil {
		return err
	}
	if err = dropLegacyProjectLoadStateTable(db); err != nil {
		return err
	}
	if err = ensureDefaultProjectCredentialsForAllUsers(db); err != nil {
		return err
	}
	if err = encryptLegacyProjectCredentialPasswords(db, cfg.CredentialKey); err != nil {
		return err
	}
	if err = initDefaultRolesAndMenus(db); err != nil {
		return err
	}
	return nil
}

func initDefaultRolesAndMenus(db *sql.DB) error {
	now := nowStr()

	_, err := db.Exec(`INSERT OR IGNORE INTO roles (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		1, "超级管理员", "系统超级管理员，拥有所有权限", now, now)
	if err != nil {
		return err
	}

	menus := []struct {
		id       int
		name     string
		path     string
		icon     string
		parentID int
		sort     int
	}{
		{1, "仪表盘", "/dashboard", "DashboardOutlined", 0, 1},
		{2, "AD管理", "/ad", "TeamOutlined", 0, 2},
		{3, "打印管理", "/print", "PrinterOutlined", 0, 3},
		{4, "VPN管理", "/vpn", "GlobalOutlined", 0, 4},
		{5, "系统管理", "/system", "SettingOutlined", 0, 5},
		{6, "用户管理", "/system/users", "UserOutlined", 5, 1},
		{7, "角色管理", "/system/roles", "SafetyOutlined", 5, 2},
		{8, "菜单管理", "/system/menus", "MenuOutlined", 5, 3},
		{9, "操作日志", "/system/logs", "FileTextOutlined", 5, 4},
	}

	for _, m := range menus {
		_, err := db.Exec(`INSERT OR IGNORE INTO menus (id, name, path, icon, parent_id, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			m.id, m.name, m.path, m.icon, m.parentID, m.sort, now, now)
		if err != nil {
			return err
		}
	}

	for i := 1; i <= 9; i++ {
		_, err := db.Exec(`INSERT OR IGNORE INTO role_menu (role_id, menu_id, created_at) VALUES (?, ?, ?)`,
			1, i, now)
		if err != nil {
			return err
		}
	}

	return nil
}

func migrateAuthTokensSchema(db *sql.DB) error {
	hasLastSeen, err := tableHasColumn(db, "auth_tokens", "last_seen_at")
	if err != nil {
		return err
	}
	if !hasLastSeen {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS auth_tokens_new (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		FOREIGN KEY(user_id) REFERENCES admins(id)
	);`); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO auth_tokens_new(token,user_id,expires_at,created_at)
		SELECT token,user_id,expires_at,created_at FROM auth_tokens`); err != nil {
		return err
	}
	if _, err = tx.Exec(`DROP TABLE auth_tokens`); err != nil {
		return err
	}
	if _, err = tx.Exec(`ALTER TABLE auth_tokens_new RENAME TO auth_tokens`); err != nil {
		return err
	}
	return tx.Commit()
}

func dropLegacyProjectLoadStateTable(db *sql.DB) error {
	_, err := db.Exec(`DROP TABLE IF EXISTS project_load_state`)
	return err
}

func migrateProjectCredentialsSchema(db *sql.DB) error {
	hasUserID, err := tableHasColumn(db, "project_credentials", "user_id")
	if err != nil {
		return err
	}
	if hasUserID {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS project_credentials_new (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		project_type TEXT NOT NULL,
		account TEXT NOT NULL DEFAULT '',
		password TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL,
		UNIQUE(user_id, project_type),
		FOREIGN KEY(user_id) REFERENCES admins(id)
	);`); err != nil {
		return err
	}

	var defaultUserID int64
	hasDefaultUser := true
	if err = tx.QueryRow(`SELECT id FROM admins ORDER BY id ASC LIMIT 1`).Scan(&defaultUserID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			hasDefaultUser = false
		} else {
			return err
		}
	}

	rows, err := tx.Query(`SELECT project_type,account,password,updated_at FROM project_credentials`)
	if err != nil {
		return err
	}

	for rows.Next() {
		var projectType, account, password, updatedAt string
		if err = rows.Scan(&projectType, &account, &password, &updatedAt); err != nil {
			_ = rows.Close()
			return err
		}
		if strings.TrimSpace(updatedAt) == "" {
			updatedAt = nowStr()
		}
		if hasDefaultUser {
			if _, err = tx.Exec(`INSERT OR IGNORE INTO project_credentials_new(user_id,project_type,account,password,updated_at) VALUES(?,?,?,?,?)`,
				defaultUserID, projectType, account, password, updatedAt,
			); err != nil {
				return err
			}
		}
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}

	if _, err = tx.Exec(`DROP TABLE project_credentials`); err != nil {
		return err
	}
	if _, err = tx.Exec(`ALTER TABLE project_credentials_new RENAME TO project_credentials`); err != nil {
		return err
	}
	return tx.Commit()
}

func tableHasColumn(db *sql.DB, tableName, columnName string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, tableName))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue interface{}
		if err = rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, columnName) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func ensureDefaultProjectCredentialsForAllUsers(db *sql.DB) error {
	rows, err := db.Query(`SELECT id FROM admins`)
	if err != nil {
		return err
	}
	userIDs := make([]int64, 0)
	for rows.Next() {
		var userID int64
		if err = rows.Scan(&userID); err != nil {
			_ = rows.Close()
			return err
		}
		userIDs = append(userIDs, userID)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, userID := range userIDs {
		if err = ensureDefaultProjectCredentialsForUser(db, userID); err != nil {
			return err
		}
	}
	return nil
}

func ensureDefaultProjectCredentialsForUser(db *sql.DB, userID int64) error {
	for _, p := range []string{"ad", "print", "vpn", "vpn_firewall"} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO project_credentials(user_id,project_type,account,password,updated_at) VALUES(?,?,?,?,?)`, userID, p, "", "", nowStr()); err != nil {
			return err
		}
	}
	return nil
}

func encryptLegacyProjectCredentialPasswords(db *sql.DB, key string) error {
	rows, err := db.Query(`SELECT rowid,password FROM project_credentials`)
	if err != nil {
		return err
	}

	type credentialRow struct {
		ID       int64
		Password string
	}
	all := make([]credentialRow, 0)
	for rows.Next() {
		var item credentialRow
		if err = rows.Scan(&item.ID, &item.Password); err != nil {
			_ = rows.Close()
			return err
		}
		all = append(all, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}

	for _, item := range all {
		pwd := strings.TrimSpace(item.Password)
		if pwd == "" || strings.HasPrefix(pwd, credentialCipherPrefix) {
			continue
		}
		encrypted, encErr := encryptCredentialPassword(pwd, key)
		if encErr != nil {
			return encErr
		}
		if _, err = db.Exec(`UPDATE project_credentials SET password=?,updated_at=? WHERE rowid=?`, encrypted, nowStr(), item.ID); err != nil {
			return err
		}
	}
	return nil
}

func encryptCredentialPassword(plain, key string) (string, error) {
	value := strings.TrimSpace(plain)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, credentialCipherPrefix) {
		return value, nil
	}

	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = crand.Read(nonce); err != nil {
		return "", err
	}
	cipherText := gcm.Seal(nil, nonce, []byte(value), nil)
	raw := append(nonce, cipherText...)
	return credentialCipherPrefix + base64.RawStdEncoding.EncodeToString(raw), nil
}

func credentialCandidateKeys(primary string) []string {
	items := make([]string, 0, 6)
	seen := map[string]bool{}
	appendKey := func(v string) {
		k := strings.TrimSpace(v)
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		items = append(items, k)
	}

	appendKey(primary)
	for _, one := range strings.Split(envString("CREDENTIAL_SECRET_FALLBACKS", ""), ",") {
		appendKey(one)
	}
	// Built-in historical defaults for smoother key migration.
	appendKey("change-me-ops-credential-secret")
	appendKey("change-this-to-your-own-secret-key")
	return items
}

func decryptCredentialPasswordRaw(raw []byte, key string) (string, error) {
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("invalid credential cipher text")
	}
	nonce, body := raw[:ns], raw[ns:]
	plain, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func decryptCredentialPassword(cipherText, key string) (string, error) {
	value := strings.TrimSpace(cipherText)
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, credentialCipherPrefix) {
		return value, nil
	}
	encoded := strings.TrimPrefix(value, credentialCipherPrefix)
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	var lastErr error
	for _, candidate := range credentialCandidateKeys(key) {
		plain, decErr := decryptCredentialPasswordRaw(raw, candidate)
		if decErr == nil {
			return plain, nil
		}
		lastErr = decErr
	}
	if lastErr == nil {
		lastErr = errors.New("credential decrypt failed")
	}
	return "", lastErr
}
