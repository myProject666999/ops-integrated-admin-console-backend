package runtime

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type Role struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type Menu struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Icon      string `json:"icon"`
	ParentID  int64  `json:"parent_id"`
	SortOrder int    `json:"sort_order"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type RoleMenuReq struct {
	MenuIDs []int64 `json:"menu_ids"`
}

type UserRoleReq struct {
	RoleIDs []int64 `json:"role_ids"`
}

type CreateRoleReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type UpdateRoleReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CreateMenuReq struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Icon      string `json:"icon"`
	ParentID  int64  `json:"parent_id"`
	SortOrder int    `json:"sort_order"`
}

type UpdateMenuReq struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Icon      string `json:"icon"`
	ParentID  int64  `json:"parent_id"`
	SortOrder int    `json:"sort_order"`
}

func (s *server) handleRolesList(w http.ResponseWriter, r *http.Request, u authedUser) {
	page := 1
	pageSize := 20

	if v := strings.TrimSpace(r.URL.Query().Get("page")); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			page = n
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("page_size")); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			pageSize = n
		}
	}
	if pageSize > 200 {
		pageSize = 200
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM roles`).Scan(&total); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色数量失败"})
		return
	}

	offset := (page - 1) * pageSize
	rows, err := s.db.Query(`SELECT id, name, description, created_at, updated_at FROM roles ORDER BY id DESC LIMIT ? OFFSET ?`, pageSize, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色列表失败"})
		return
	}
	defer rows.Close()

	items := make([]Role, 0)
	for rows.Next() {
		var role Role
		if err = rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取角色数据失败"})
			return
		}
		items = append(items, role)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":     items,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func (s *server) handleRoleCreate(w http.ResponseWriter, r *http.Request, u authedUser) {
	var req CreateRoleReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "角色名称不能为空"})
		return
	}

	now := nowStr()
	res, err := s.db.Exec(`INSERT INTO roles (name, description, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		name, strings.TrimSpace(req.Description), now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, apiError{Error: "角色名称已存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "创建角色失败"})
		return
	}

	roleID, _ := res.LastInsertId()
	s.logAction(u.ID, u.Username, "create_role", "", "创建角色: "+name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":      roleID,
		"message": "创建成功",
	})
}

func (s *server) handleRoleUpdate(w http.ResponseWriter, r *http.Request, u authedUser) {
	roleIDStr := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	var req UpdateRoleReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "角色名称不能为空"})
		return
	}

	now := nowStr()
	res, err := s.db.Exec(`UPDATE roles SET name = ?, description = ?, updated_at = ? WHERE id = ?`,
		name, strings.TrimSpace(req.Description), now, roleID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, apiError{Error: "角色名称已存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "更新角色失败"})
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, apiError{Error: "角色不存在"})
		return
	}

	s.logAction(u.ID, u.Username, "update_role", "", "更新角色: "+name)
	writeJSON(w, http.StatusOK, map[string]string{"message": "更新成功"})
}

func (s *server) handleRoleDelete(w http.ResponseWriter, r *http.Request, u authedUser) {
	roleIDStr := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	if roleID == 1 {
		writeJSON(w, http.StatusForbidden, apiError{Error: "不能删除超级管理员角色"})
		return
	}

	res, err := s.db.Exec(`DELETE FROM roles WHERE id = ?`, roleID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "删除角色失败"})
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, apiError{Error: "角色不存在"})
		return
	}

	s.logAction(u.ID, u.Username, "delete_role", "", "删除角色ID: "+strconv.FormatInt(roleID, 10))
	writeJSON(w, http.StatusOK, map[string]string{"message": "删除成功"})
}

func (s *server) handleRoleGet(w http.ResponseWriter, r *http.Request, u authedUser) {
	roleIDStr := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	var role Role
	err = s.db.QueryRow(`SELECT id, name, description, created_at, updated_at FROM roles WHERE id = ?`, roleID).
		Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, apiError{Error: "角色不存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询角色失败"})
		return
	}

	writeJSON(w, http.StatusOK, role)
}

func (s *server) handleMenusList(w http.ResponseWriter, r *http.Request, u authedUser) {
	rows, err := s.db.Query(`SELECT id, name, path, icon, parent_id, sort_order, created_at, updated_at FROM menus ORDER BY sort_order ASC`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询菜单列表失败"})
		return
	}
	defer rows.Close()

	items := make([]Menu, 0)
	for rows.Next() {
		var menu Menu
		if err = rows.Scan(&menu.ID, &menu.Name, &menu.Path, &menu.Icon, &menu.ParentID, &menu.SortOrder, &menu.CreatedAt, &menu.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取菜单数据失败"})
			return
		}
		items = append(items, menu)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
	})
}

func (s *server) handleMenuCreate(w http.ResponseWriter, r *http.Request, u authedUser) {
	var req CreateMenuReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	name := strings.TrimSpace(req.Name)
	path := strings.TrimSpace(req.Path)
	if name == "" || path == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "菜单名称和路径不能为空"})
		return
	}

	now := nowStr()
	res, err := s.db.Exec(`INSERT INTO menus (name, path, icon, parent_id, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		name, path, strings.TrimSpace(req.Icon), req.ParentID, req.SortOrder, now, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "创建菜单失败"})
		return
	}

	menuID, _ := res.LastInsertId()
	s.logAction(u.ID, u.Username, "create_menu", "", "创建菜单: "+name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":      menuID,
		"message": "创建成功",
	})
}

func (s *server) handleMenuUpdate(w http.ResponseWriter, r *http.Request, u authedUser) {
	menuIDStr := strings.TrimPrefix(r.URL.Path, "/api/menus/")
	menuID, err := strconv.ParseInt(menuIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的菜单ID"})
		return
	}

	var req UpdateMenuReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	name := strings.TrimSpace(req.Name)
	path := strings.TrimSpace(req.Path)
	if name == "" || path == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "菜单名称和路径不能为空"})
		return
	}

	now := nowStr()
	res, err := s.db.Exec(`UPDATE menus SET name = ?, path = ?, icon = ?, parent_id = ?, sort_order = ?, updated_at = ? WHERE id = ?`,
		name, path, strings.TrimSpace(req.Icon), req.ParentID, req.SortOrder, now, menuID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "更新菜单失败"})
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, apiError{Error: "菜单不存在"})
		return
	}

	s.logAction(u.ID, u.Username, "update_menu", "", "更新菜单: "+name)
	writeJSON(w, http.StatusOK, map[string]string{"message": "更新成功"})
}

func (s *server) handleMenuDelete(w http.ResponseWriter, r *http.Request, u authedUser) {
	menuIDStr := strings.TrimPrefix(r.URL.Path, "/api/menus/")
	menuID, err := strconv.ParseInt(menuIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的菜单ID"})
		return
	}

	var childCount int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM menus WHERE parent_id = ?`, menuID).Scan(&childCount); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询子菜单失败"})
		return
	}
	if childCount > 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请先删除子菜单"})
		return
	}

	res, err := s.db.Exec(`DELETE FROM menus WHERE id = ?`, menuID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "删除菜单失败"})
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		writeJSON(w, http.StatusNotFound, apiError{Error: "菜单不存在"})
		return
	}

	s.logAction(u.ID, u.Username, "delete_menu", "", "删除菜单ID: "+strconv.FormatInt(menuID, 10))
	writeJSON(w, http.StatusOK, map[string]string{"message": "删除成功"})
}

func (s *server) handleRoleMenusGet(w http.ResponseWriter, r *http.Request, u authedUser) {
	roleIDStr := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	roleIDStr = strings.TrimSuffix(roleIDStr, "/menus")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	rows, err := s.db.Query(`SELECT menu_id FROM role_menu WHERE role_id = ?`, roleID)
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
		"menu_ids": menuIDs,
	})
}

func (s *server) handleRoleMenusUpdate(w http.ResponseWriter, r *http.Request, u authedUser) {
	roleIDStr := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	roleIDStr = strings.TrimSuffix(roleIDStr, "/menus")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的角色ID"})
		return
	}

	var req RoleMenuReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "开启事务失败"})
		return
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`DELETE FROM role_menu WHERE role_id = ?`, roleID); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "清除角色菜单失败"})
		return
	}

	now := nowStr()
	for _, menuID := range req.MenuIDs {
		if _, err = tx.Exec(`INSERT INTO role_menu (role_id, menu_id, created_at) VALUES (?, ?, ?)`,
			roleID, menuID, now); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "分配角色菜单失败"})
			return
		}
	}

	if err = tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "提交事务失败"})
		return
	}

	s.logAction(u.ID, u.Username, "update_role_menus", "", "更新角色菜单权限, 角色ID: "+strconv.FormatInt(roleID, 10))
	writeJSON(w, http.StatusOK, map[string]string{"message": "权限分配成功"})
}

func (s *server) handleUserRolesGet(w http.ResponseWriter, r *http.Request, u authedUser) {
	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	userIDStr = strings.TrimSuffix(userIDStr, "/roles")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的用户ID"})
		return
	}

	rows, err := s.db.Query(`SELECT role_id FROM user_role WHERE user_id = ?`, userID)
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
		"role_ids": roleIDs,
	})
}

func (s *server) handleUserRolesUpdate(w http.ResponseWriter, r *http.Request, u authedUser) {
	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	userIDStr = strings.TrimSuffix(userIDStr, "/roles")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "无效的用户ID"})
		return
	}

	var req UserRoleReq
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请求体格式错误"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "开启事务失败"})
		return
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`DELETE FROM user_role WHERE user_id = ?`, userID); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "清除用户角色失败"})
		return
	}

	now := nowStr()
	for _, roleID := range req.RoleIDs {
		if _, err = tx.Exec(`INSERT INTO user_role (user_id, role_id, created_at) VALUES (?, ?, ?)`,
			userID, roleID, now); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "分配用户角色失败"})
			return
		}
	}

	if err = tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "提交事务失败"})
		return
	}

	s.logAction(u.ID, u.Username, "update_user_roles", "", "更新用户角色, 用户ID: "+strconv.FormatInt(userID, 10))
	writeJSON(w, http.StatusOK, map[string]string{"message": "角色分配成功"})
}

func (s *server) handleUserMenus(w http.ResponseWriter, r *http.Request, u authedUser) {
	rows, err := s.db.Query(`
		SELECT DISTINCT m.id, m.name, m.path, m.icon, m.parent_id, m.sort_order, m.created_at, m.updated_at
		FROM menus m
		INNER JOIN role_menu rm ON m.id = rm.menu_id
		INNER JOIN user_role ur ON rm.role_id = ur.role_id
		WHERE ur.user_id = ?
		ORDER BY m.sort_order ASC
	`, u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "查询用户菜单失败"})
		return
	}
	defer rows.Close()

	items := make([]Menu, 0)
	for rows.Next() {
		var menu Menu
		if err = rows.Scan(&menu.ID, &menu.Name, &menu.Path, &menu.Icon, &menu.ParentID, &menu.SortOrder, &menu.CreatedAt, &menu.UpdatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "读取用户菜单失败"})
			return
		}
		items = append(items, menu)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
	})
}
