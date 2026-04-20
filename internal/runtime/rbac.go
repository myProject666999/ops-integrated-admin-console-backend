package runtime

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type roleRow struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int    `json:"status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type menuRow struct {
	ID        int64    `json:"id"`
	ParentID  int64    `json:"parent_id"`
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Icon      string   `json:"icon"`
	SortOrder int      `json:"sort_order"`
	Status    int      `json:"status"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
	Children  []menuRow `json:"children,omitempty"`
}

type roleCreateReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int    `json:"status"`
}

type roleUpdateReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int    `json:"status"`
}

type menuCreateReq struct {
	ParentID  int64  `json:"parent_id"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Icon      string `json:"icon"`
	SortOrder int    `json:"sort_order"`
	Status    int    `json:"status"`
}

type menuUpdateReq struct {
	ParentID  int64  `json:"parent_id"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Icon      string `json:"icon"`
	SortOrder int    `json:"sort_order"`
	Status    int    `json:"status"`
}

type assignRoleMenusReq struct {
	MenuIDs []int64 `json:"menu_ids"`
}

type assignUserRolesReq struct {
	RoleIDs []int64 `json:"role_ids"`
}

func (s *server) handleRoleList(w http.ResponseWriter, r *http.Request, _ authedUser) {
	page := 1
	pageSize := 20
	if v := strings.TrimSpace(r.URL.Query().Get("page")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("page_size")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			pageSize = n
		}
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	where := ""
	args := make([]interface{}, 0)
	if name != "" {
		where = " WHERE name LIKE ?"
		args = append(args, "%"+name+"%")
	}

	var total int
	countQuery := "SELECT COUNT(1) FROM roles" + where
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色失败"})
		return
	}

	offset := (page - 1) * pageSize
	query := "SELECT id,name,COALESCE(description,''),status,created_at,updated_at FROM roles" + where + " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色失败"})
		return
	}
	defer rows.Close()

	items := make([]roleRow, 0)
	for rows.Next() {
		var row roleRow
		if err = rows.Scan(&row.ID, &row.Name, &row.Description, &row.Status, &row.CreatedAt, &row.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取角色失败"})
			return
		}
		items = append(items, row)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":     items,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func (s *server) handleRoleCreate(w http.ResponseWriter, r *http.Request, u authedUser) {
	var req roleCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "角色名称不能为空"})
		return
	}
	if len(name) > 50 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "角色名称不能超过50个字符"})
		return
	}
	status := req.Status
	if status != 0 && status != 1 {
		status = 1
	}

	now := nowStr()
	res, err := s.db.Exec("INSERT INTO roles(name,description,status,created_at,updated_at) VALUES(?,?,?,?,?)",
		name, strings.TrimSpace(req.Description), status, now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, apiError{Error: "角色名称已存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "创建角色失败"})
		return
	}
	id, _ := res.LastInsertId()
	s.logAction(u.ID, u.Username, "role_create", "", "创建角色: "+name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":          id,
		"name":        name,
		"description": req.Description,
		"status":      status,
		"created_at":  now,
		"updated_at":  now,
	})
}

func (s *server) handleRoleUpdate(w http.ResponseWriter, r *http.Request, u authedUser) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/roles/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	var req roleUpdateReq
	if err = decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "角色名称不能为空"})
		return
	}
	if len(name) > 50 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "角色名称不能超过50个字符"})
		return
	}

	var existID int64
	if err = s.db.QueryRow("SELECT id FROM roles WHERE id=?", id).Scan(&existID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "角色不存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色失败"})
		return
	}

	status := req.Status
	if status != 0 && status != 1 {
		status = 1
	}

	now := nowStr()
	if _, err = s.db.Exec("UPDATE roles SET name=?,description=?,status=?,updated_at=? WHERE id=?",
		name, strings.TrimSpace(req.Description), status, now, id); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, apiError{Error: "角色名称已存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "更新角色失败"})
		return
	}

	s.logAction(u.ID, u.Username, "role_update", "", "更新角色: "+name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":          id,
		"name":        name,
		"description": req.Description,
		"status":      status,
		"updated_at":  now,
	})
}

func (s *server) handleRoleDelete(w http.ResponseWriter, r *http.Request, u authedUser) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/roles/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	var name string
	if err = s.db.QueryRow("SELECT name FROM roles WHERE id=?", id).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "角色不存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色失败"})
		return
	}

	if _, err = s.db.Exec("DELETE FROM roles WHERE id=?", id); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "删除角色失败"})
		return
	}

	s.logAction(u.ID, u.Username, "role_delete", "", "删除角色: "+name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleMenuList(w http.ResponseWriter, r *http.Request, _ authedUser) {
	statusStr := strings.TrimSpace(r.URL.Query().Get("status"))
	where := ""
	args := make([]interface{}, 0)
	if statusStr != "" {
		if status, err := strconv.Atoi(statusStr); err == nil {
			where = " WHERE status=?"
			args = append(args, status)
		}
	}

	query := "SELECT id,parent_id,name,COALESCE(path,''),COALESCE(icon,''),sort_order,status,created_at,updated_at FROM menus" + where + " ORDER BY sort_order ASC, id ASC"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询菜单失败"})
		return
	}
	defer rows.Close()

	items := make([]menuRow, 0)
	for rows.Next() {
		var row menuRow
		if err = rows.Scan(&row.ID, &row.ParentID, &row.Name, &row.Path, &row.Icon, &row.SortOrder, &row.Status, &row.CreatedAt, &row.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取菜单失败"})
			return
		}
		items = append(items, row)
	}

	tree := buildMenuTree(items, 0)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"tree":  tree,
	})
}

func buildMenuTree(items []menuRow, parentID int64) []menuRow {
	tree := make([]menuRow, 0)
	for _, item := range items {
		if item.ParentID == parentID {
			children := buildMenuTree(items, item.ID)
			if len(children) > 0 {
				item.Children = children
			}
			tree = append(tree, item)
		}
	}
	return tree
}

func (s *server) handleMenuCreate(w http.ResponseWriter, r *http.Request, u authedUser) {
	var req menuCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "菜单名称不能为空"})
		return
	}
	if len(name) > 50 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "菜单名称不能超过50个字符"})
		return
	}

	status := req.Status
	if status != 0 && status != 1 {
		status = 1
	}

	now := nowStr()
	res, err := s.db.Exec("INSERT INTO menus(parent_id,name,path,icon,sort_order,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
		req.ParentID, name, strings.TrimSpace(req.Path), strings.TrimSpace(req.Icon), req.SortOrder, status, now, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "创建菜单失败"})
		return
	}
	id, _ := res.LastInsertId()
	s.logAction(u.ID, u.Username, "menu_create", "", "创建菜单: "+name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         id,
		"parent_id":  req.ParentID,
		"name":       name,
		"path":       req.Path,
		"icon":       req.Icon,
		"sort_order": req.SortOrder,
		"status":     status,
		"created_at": now,
		"updated_at": now,
	})
}

func (s *server) handleMenuUpdate(w http.ResponseWriter, r *http.Request, u authedUser) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/menus/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的菜单ID"})
		return
	}

	var req menuUpdateReq
	if err = decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "菜单名称不能为空"})
		return
	}
	if len(name) > 50 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "菜单名称不能超过50个字符"})
		return
	}

	var existID int64
	if err = s.db.QueryRow("SELECT id FROM menus WHERE id=?", id).Scan(&existID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "菜单不存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询菜单失败"})
		return
	}

	status := req.Status
	if status != 0 && status != 1 {
		status = 1
	}

	now := nowStr()
	if _, err = s.db.Exec("UPDATE menus SET parent_id=?,name=?,path=?,icon=?,sort_order=?,status=?,updated_at=? WHERE id=?",
		req.ParentID, name, strings.TrimSpace(req.Path), strings.TrimSpace(req.Icon), req.SortOrder, status, now, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "更新菜单失败"})
		return
	}

	s.logAction(u.ID, u.Username, "menu_update", "", "更新菜单: "+name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         id,
		"parent_id":  req.ParentID,
		"name":       name,
		"path":       req.Path,
		"icon":       req.Icon,
		"sort_order": req.SortOrder,
		"status":     status,
		"updated_at": now,
	})
}

func (s *server) handleMenuDelete(w http.ResponseWriter, r *http.Request, u authedUser) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/menus/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的菜单ID"})
		return
	}

	var name string
	if err = s.db.QueryRow("SELECT name FROM menus WHERE id=?", id).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "菜单不存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询菜单失败"})
		return
	}

	var childCount int
	if err = s.db.QueryRow("SELECT COUNT(1) FROM menus WHERE parent_id=?", id).Scan(&childCount); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询子菜单失败"})
		return
	}
	if childCount > 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "存在子菜单，无法删除"})
		return
	}

	if _, err = s.db.Exec("DELETE FROM menus WHERE id=?", id); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "删除菜单失败"})
		return
	}

	s.logAction(u.ID, u.Username, "menu_delete", "", "删除菜单: "+name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleAssignRoleMenus(w http.ResponseWriter, r *http.Request, u authedUser) {
	roleIDStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/roles/")
	roleIDStr = strings.TrimSuffix(roleIDStr, "/menus")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	var req assignRoleMenusReq
	if err = decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	var existID int64
	if err = s.db.QueryRow("SELECT id FROM roles WHERE id=?", roleID).Scan(&existID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "角色不存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色失败"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "开启事务失败"})
		return
	}
	defer tx.Rollback()

	if _, err = tx.Exec("DELETE FROM role_menu WHERE role_id=?", roleID); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "清除角色菜单失败"})
		return
	}

	now := nowStr()
	for _, menuID := range req.MenuIDs {
		if menuID <= 0 {
			continue
		}
		if _, err = tx.Exec("INSERT INTO role_menu(role_id,menu_id,created_at) VALUES(?,?,?)", roleID, menuID, now); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "分配角色菜单失败"})
			return
		}
	}

	if err = tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "提交事务失败"})
		return
	}

	s.logAction(u.ID, u.Username, "assign_role_menus", "", "分配角色菜单")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleGetRoleMenus(w http.ResponseWriter, r *http.Request, _ authedUser) {
	roleIDStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/roles/")
	roleIDStr = strings.TrimSuffix(roleIDStr, "/menus")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	rows, err := s.db.Query("SELECT menu_id FROM role_menu WHERE role_id=?", roleID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色菜单失败"})
		return
	}
	defer rows.Close()

	menuIDs := make([]int64, 0)
	for rows.Next() {
		var menuID int64
		if err = rows.Scan(&menuID); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取角色菜单失败"})
			return
		}
		menuIDs = append(menuIDs, menuID)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"role_id":  roleID,
		"menu_ids": menuIDs,
	})
}

func (s *server) handleAssignUserRoles(w http.ResponseWriter, r *http.Request, u authedUser) {
	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/users/")
	userIDStr = strings.TrimSuffix(userIDStr, "/roles")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的用户ID"})
		return
	}

	var req assignUserRolesReq
	if err = decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	var existID int64
	if err = s.db.QueryRow("SELECT id FROM admins WHERE id=?", userID).Scan(&existID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "用户不存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询用户失败"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "开启事务失败"})
		return
	}
	defer tx.Rollback()

	if _, err = tx.Exec("DELETE FROM role_user WHERE user_id=?", userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "清除用户角色失败"})
		return
	}

	now := nowStr()
	for _, roleID := range req.RoleIDs {
		if roleID <= 0 {
			continue
		}
		if _, err = tx.Exec("INSERT INTO role_user(role_id,user_id,created_at) VALUES(?,?,?)", roleID, userID, now); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "分配用户角色失败"})
			return
		}
	}

	if err = tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "提交事务失败"})
		return
	}

	s.logAction(u.ID, u.Username, "assign_user_roles", "", "分配用户角色")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleGetUserRoles(w http.ResponseWriter, r *http.Request, _ authedUser) {
	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/users/")
	userIDStr = strings.TrimSuffix(userIDStr, "/roles")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的用户ID"})
		return
	}

	rows, err := s.db.Query("SELECT role_id FROM role_user WHERE user_id=?", userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询用户角色失败"})
		return
	}
	defer rows.Close()

	roleIDs := make([]int64, 0)
	for rows.Next() {
		var roleID int64
		if err = rows.Scan(&roleID); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取用户角色失败"})
			return
		}
		roleIDs = append(roleIDs, roleID)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":  userID,
		"role_ids": roleIDs,
	})
}

func (s *server) handleGetUserMenus(w http.ResponseWriter, r *http.Request, _ authedUser) {
	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/rbac/users/")
	userIDStr = strings.TrimSuffix(userIDStr, "/menus")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的用户ID"})
		return
	}

	query := `SELECT DISTINCT m.id,m.parent_id,m.name,COALESCE(m.path,''),COALESCE(m.icon,''),m.sort_order,m.status,m.created_at,m.updated_at
		FROM menus m
		INNER JOIN role_menu rm ON m.id = rm.menu_id
		INNER JOIN role_user ru ON rm.role_id = ru.role_id
		WHERE ru.user_id = ? AND m.status = 1
		ORDER BY m.sort_order ASC, m.id ASC`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询用户菜单失败"})
		return
	}
	defer rows.Close()

	items := make([]menuRow, 0)
	for rows.Next() {
		var row menuRow
		if err = rows.Scan(&row.ID, &row.ParentID, &row.Name, &row.Path, &row.Icon, &row.SortOrder, &row.Status, &row.CreatedAt, &row.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取用户菜单失败"})
			return
		}
		items = append(items, row)
	}

	tree := buildMenuTree(items, 0)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"tree":  tree,
	})
}

func (s *server) handleGetCurrentUserMenus(w http.ResponseWriter, _ *http.Request, u authedUser) {
	query := `SELECT DISTINCT m.id,m.parent_id,m.name,COALESCE(m.path,''),COALESCE(m.icon,''),m.sort_order,m.status,m.created_at,m.updated_at
		FROM menus m
		INNER JOIN role_menu rm ON m.id = rm.menu_id
		INNER JOIN role_user ru ON rm.role_id = ru.role_id
		WHERE ru.user_id = ? AND m.status = 1
		ORDER BY m.sort_order ASC, m.id ASC`

	rows, err := s.db.Query(query, u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询用户菜单失败"})
		return
	}
	defer rows.Close()

	items := make([]menuRow, 0)
	for rows.Next() {
		var row menuRow
		if err = rows.Scan(&row.ID, &row.ParentID, &row.Name, &row.Path, &row.Icon, &row.SortOrder, &row.Status, &row.CreatedAt, &row.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取用户菜单失败"})
			return
		}
		items = append(items, row)
	}

	tree := buildMenuTree(items, 0)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"tree":  tree,
	})
}
