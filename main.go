package main

import (
	"database/sql"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	chart "github.com/wcharczuk/go-chart/v2"
	"golang.org/x/crypto/bcrypt"
)

// ================= Struct =====================
type Categories struct {
	ID    int
	Name  string
	Index int
}

type User struct {
	ID         int
	Name       string
	Email      string
	Password   string
	IsActive   int
	IsBorrowed int
	Role       string
	Index      int
}
type CountsUser struct {
	CountUser      int
	CountActive    int
	CountNonactive int
}

type Book struct {
	ID           int
	Title        string
	Isbn         string
	CategoryId   int
	Img          string
	CategoryName string
	IsBorrowed   int
	Index        int
}

type BookDetail struct {
	ID               int
	Title            string
	Isbn             string
	Img              string
	CategoryName     string
	StartDate        time.Time
	EndDate          time.Time
	ActualReturnDate sql.NullTime
	StartStr         string
	EndStr           string
	ActualReturnStr  string
	Penalty          float64
}

type BooksCount struct {
	BookCount     int
	BookAvailable int
	BookBorrowed  int
}

type BookingCount struct {
	BookingCount int
}

type BookingDetail struct {
	ID               int
	UserName         string
	BookTitles       string
	StartDate        time.Time
	EndDate          time.Time
	ActualReturnDate sql.NullTime
	TotalBooks       float64
	Index            int
	StartStr         string
	EndStr           string
	ActualReturnStr  string
}

type Settings struct {
	PenaltyFee float64
}

// ================= Middleware =====================
func AuthMiddleware(ctx *gin.Context) {

	tokenStr, err := ctx.Cookie("token")

	if err != nil {
		ctx.Redirect(http.StatusFound, "/login")
		ctx.Abort()
		return
	}

	secret := os.Getenv("JWT_SECRET")

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unsupported signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	fmt.Println("Parse Error =", err)

	if err != nil || !token.Valid {
		fmt.Println("Middleware: Token invalid")
		ctx.Redirect(http.StatusFound, "/login")
		ctx.Abort()
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		fmt.Println("Middleware: Claims invalid")
		ctx.Redirect(http.StatusFound, "/login")
		ctx.Abort()
		return
	}

	ctx.Set("Data", claims)
	ctx.Next()

}

// ================ ADMIN===============
func AdminOnly(ctx *gin.Context) {
	data, exists := ctx.Get("Data")
	if !exists {
		ctx.Redirect(http.StatusFound, "/login")
		ctx.Abort()
		return
	}

	claims := data.(jwt.MapClaims)
	role, ok := claims["role"].(string)

	fmt.Println("AdminOnly role =", role)

	if !ok || role != "admin" {
		ctx.Redirect(http.StatusFound, "/forbidden")
		ctx.Abort()
		return
	}

	ctx.Next()
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(".env file not found")
	}

	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASS")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	name := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", user, pass, host, port, name)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Failed to Open Connection")
	}

	app := gin.Default()
	app.Use(gin.Logger())
	app.Use(gin.Recovery())

	app.LoadHTMLGlob("views/*")
	app.Static("/img", "./img")
	app.Static("/charts", "./public/charts")

	//  ============== LOGIN ========================

	app.GET("/login", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "login.html", nil)
	})

	app.POST("/login", func(ctx *gin.Context) {
		ctx.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		ctx.Header("Pragma", "no-cache")
		ctx.Header("Expires", "0")

		email := strings.TrimSpace(ctx.PostForm("email"))
		password := strings.TrimSpace(ctx.PostForm("password"))

		if email == "" || password == "" {
			ctx.HTML(http.StatusBadRequest, "login.html", gin.H{
				"error": "Email dan Password wajib di isi",
				"email": email,
			})
			return
		}

		jwtSecret := os.Getenv("JWT_SECRET")
		adminEmail := os.Getenv("ADMIN_EMAIL")

		adminPassHash := strings.TrimSpace(os.Getenv("ADMIN_PASSWORD"))

		if email == adminEmail {
			err := bcrypt.CompareHashAndPassword([]byte(adminPassHash), []byte(password))
			if err != nil {
				ctx.HTML(http.StatusUnauthorized, "login.html", gin.H{
					"error": "Password Admin salah",
					"email": email,
				})
				return
			}

			token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"email": adminEmail,
				"role":  "admin",
				"exp":   time.Now().Add(24 * time.Hour).Unix(),
			}).SignedString([]byte(jwtSecret))

			ctx.SetCookie("token", token, 86400, "/", "", false, true)
			ctx.Redirect(http.StatusFound, "/user")
			return
		}

		var user User
		err := db.QueryRow(`SELECT id, name, email, password, is_active, role FROM users WHERE email = ?`, email).
			Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.IsActive, &user.Role)

		if err != nil {
			if err == sql.ErrNoRows {
				ctx.HTML(http.StatusUnauthorized, "login.html", gin.H{
					"error": "Email tidak terdaftar",
					"email": email,
				})
				return
			}
			ctx.HTML(http.StatusInternalServerError, "login.html", gin.H{
				"error": "Terjadi kesalahan server. Silakan coba lagi.",
				"email": email,
			})
			return
		}

		if user.IsActive == 0 {
			ctx.HTML(http.StatusForbidden, "login.html", gin.H{
				"error": "Akun tidak aktif. Hubungi Admin.",
				"email": email,
			})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			ctx.HTML(http.StatusUnauthorized, "login.html", gin.H{
				"error": "Password salah",
				"email": email,
			})
			return
		}

		token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
			"exp":   time.Now().Add(24 * time.Hour).Unix(),
		}).SignedString([]byte(jwtSecret))

		fmt.Println("Token User =", token)

		ctx.SetCookie("token", token, 86400, "/", "", false, true)

		if user.Role == "admin" {
			ctx.Redirect(http.StatusFound, "/user")
			return
		}

		ctx.Redirect(http.StatusFound, "/home")
	})

	//  =================== LOGOUT ===================
	app.POST("/logout", func(c *gin.Context) {

		c.SetCookie("token", "", -1, "/", "", false, true)
		c.Redirect(http.StatusFound, "/login")
	})
	// =============== FORBIDDIN =========================
	app.GET("/forbidden", func(ctx *gin.Context) {
		ctx.HTML(http.StatusForbidden, "forbidden.html", gin.H{
			"error": "Akses ditolak: Anda bukan admin",
		})
	})

	// ================= DASHBOARD ==================
	app.GET("/dashboard", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		selected := ctx.Query("tahun")

		/* =========================
		GET AVAILABLE YEARS
		========================= */
		queryYear := `
			SELECT DISTINCT YEAR(start_date) AS year
			FROM bookings
			ORDER BY year ASC
		`

		rowsYear, err := db.Query(queryYear)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
				"error": "Gagal memuat data tahun. Silakan coba lagi nanti.",
			})
			return
		}
		defer rowsYear.Close()

		var years []int
		for rowsYear.Next() {
			var y int
			if err := rowsYear.Scan(&y); err != nil {
				ctx.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
					"error": "Gagal memproses data tahun. Silakan coba lagi nanti.",
				})
				return
			}
			years = append(years, y)
		}

		/* =========================
		SELECT YEAR
		========================= */
		var year int
		if selected != "" {
			year, _ = strconv.Atoi(selected)
		} else if len(years) > 0 {
			year = years[len(years)-1]
		} else {
			year = time.Now().Year()
		}

		/* =========================
		CHART DATA (BOOKINGS)
		========================= */
		queryChart := `
			SELECT MONTH(start_date) AS month, COUNT(*) AS total
			FROM bookings
			WHERE YEAR(start_date) = ?
			GROUP BY MONTH(start_date)
			ORDER BY MONTH(start_date)
		`

		rowsChart, err := db.Query(queryChart, year)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
				"error": "Gagal memuat data chart. Silakan coba lagi nanti.",
			})
			return
		}
		defer rowsChart.Close()

		chartData := make([]float64, 12)
		for rowsChart.Next() {
			var month, total int
			if err := rowsChart.Scan(&month, &total); err != nil {
				ctx.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
					"error": "Gagal memproses data chart. Silakan coba lagi nanti.",
				})
				return
			}
			chartData[month-1] = float64(total)
		}

		/* =========================
		GENERATE BAR CHART
		========================= */
		chartDir := "./public/charts"
		err = os.MkdirAll(chartDir, 0755)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
				"error": "Gagal membuat folder chart. Silakan coba lagi nanti.",
			})
			return
		}

		chartFile := fmt.Sprintf("./public/charts/chart_%d.png", year)
		f, err := os.Create(chartFile)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
				"error": "Gagal membuat file chart. Silakan coba lagi nanti.",
			})
			return
		}
		defer f.Close()

		graph := chart.BarChart{
			Title:  fmt.Sprintf("Peminjaman Buku %d", year),
			Height: 400,
			Width:  800,
		}

		monthLabels := []string{
			"Jan", "Feb", "Mar", "Apr", "Mei", "Jun",
			"Jul", "Agu", "Sep", "Okt", "Nov", "Des",
		}

		for i, v := range chartData {
			graph.Bars = append(graph.Bars, chart.Value{
				Label: monthLabels[i],
				Value: v,
			})
		}

		graph.Render(chart.PNG, f)

		/* =========================
		ONTIME VS LATE
		========================= */
		queryPercentage := `
			SELECT
				COUNT(*) AS total,
				COUNT(CASE WHEN actual_return_date <= end_date THEN 1 END) AS ontime,
				COUNT(CASE WHEN actual_return_date > end_date THEN 1 END) AS late
			FROM bookings
			WHERE YEAR(start_date) = ?
		`

		var total, ontime, late int
		err = db.QueryRow(queryPercentage, year).Scan(&total, &ontime, &late)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
				"error": "Gagal memuat persentase ontime/late. Silakan coba lagi nanti.",
			})
			return
		}

		var pctOntime, pctLate int
		if total > 0 {
			pctOntime = (ontime * 100) / total
			pctLate = (late * 100) / total
		}

		/* =========================
		TOTAL PENALTY
		========================= */
		queryPenalty := `
			SELECT COALESCE(SUM(penalty_fee), 0)
			FROM bookings
			WHERE actual_return_date IS NOT NULL
		`

		var totalPenalty float64
		err = db.QueryRow(queryPenalty).Scan(&totalPenalty)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{
				"error": "Gagal memuat total penalty. Silakan coba lagi nanti.",
			})
			return
		}

		/* =========================
		RENDER VIEW
		========================= */
		ctx.HTML(http.StatusOK, "dashboard.html", gin.H{
			"Years":        years,
			"Year":         year,
			"ChartImage":   "/charts/chart_" + strconv.Itoa(year) + ".png",
			"Ontime":       pctOntime,
			"Late":         pctLate,
			"TotalPenalty": totalPenalty,
			"error":        "",
		})
	})

	// ================= Categories ================

	app.GET("/categories", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		search := ctx.Query("search")
		formatSearch := "%" + search + "%"
		page, err := strconv.Atoi(ctx.Query("page"))
		if err != nil || page < 1 {
			page = 1
		}
		limit := 8
		offset := (page - 1) * limit

		rows, err := db.Query("SELECT id,name FROM categories WHERE name LIKE ? ORDER BY id ASC LIMIT ? OFFSET ? ", formatSearch, limit, offset)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "categories_admin.html", gin.H{
				"Categories": []Categories{},
				"Search":     search,
				"Total":      0,
				"Pages":      []int{},
				"Page":       page,
				"error":      "Gagal mengambil data kategori: " + err.Error(),
			})
			return
		}

		var total int
		err = db.QueryRow("SELECT Count(*) as total FROM categories WHERE name LIKE ?", formatSearch).Scan(&total)
		if err != nil {
			errMsg := "Terjadi kesalahan"
			if err == sql.ErrNoRows {
				errMsg = "Kategori tidak ditemukan"
			} else {
				errMsg = err.Error()

			}
			ctx.HTML(http.StatusOK, "categories_admin.html", gin.H{
				"Categories": []Categories{},
				"Search":     search,
				"Total":      0,
				"Pages":      []int{},
				"Page":       page,
				"error":      errMsg,
			})
			return
		}

		var categories []Categories
		i := offset + 1
		for rows.Next() {
			var cat Categories
			if err := rows.Scan(&cat.ID, &cat.Name); err != nil {
				ctx.HTML(http.StatusInternalServerError, "categories_admin.html", gin.H{
					"Categories": categories,
					"Search":     search,
					"Total":      total,
					"Pages":      []int{},
					"Page":       page,
					"error":      "Gagal membaca data kategori: " + err.Error(),
				})
				return
			}
			cat.Index = i
			i++
			categories = append(categories, cat)
		}

		totalPage := int(math.Ceil(float64(total) / float64(limit)))
		if page > totalPage && totalPage != 0 {
			ctx.Redirect(http.StatusFound, fmt.Sprintf("bookings?page=%d&search=%s", totalPage, url.QueryEscape(search)))
			return
		}
		pages := make([]int, totalPage)
		for i := 0; i < totalPage; i++ {
			pages[i] = i + 1
		}

		ctx.HTML(http.StatusOK, "categories_admin.html", gin.H{
			"Categories": categories,
			"Search":     search,
			"Total":      total,
			"Pages":      pages,
			"Page":       page,
		})
	})

	app.GET("/categories/create", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		page := ctx.Query("page")
		search := ctx.Query("search")
		ctx.HTML(http.StatusOK, "create_categories.html", gin.H{
			"Page":   page,
			"Search": search,
		})
	})

	app.POST("/categories/create", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		name := ctx.PostForm("name")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		name = strings.TrimSpace(name)
		if name == "" {
			ctx.HTML(http.StatusBadRequest, "create_categories.html", gin.H{
				"error": "Nama kategori tidak boleh kosong",
			})
			return
		}

		results, err := db.Exec("INSERT INTO categories (name) VALUES (?)", name)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_categories.html", gin.H{
				"error": "Terjadi kesalahan saat membuat kategori: " + err.Error(),
			})
			return
		}

		row, err := results.RowsAffected()
		if err != nil || row == 0 {
			ctx.HTML(http.StatusInternalServerError, "create_categories.html", gin.H{
				"error": "Gagal membuat kategori",
			})
			return
		}

		ctx.Redirect(http.StatusFound, "/categories?page="+page+"&search="+search)
	})

	app.GET("/categories/update/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		page := ctx.Query("page")
		search := ctx.Query("search")

		var cat Categories

		err := db.QueryRow("SELECT id,name FROM categories WHERE id = ?", id).Scan(&cat.ID, &cat.Name)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.HTML(http.StatusNotFound, "categories_admin.html", gin.H{
					"Categories": []Categories{}, // list kosong
					"Pages":      []int{},
					"Page":       page,
					"Search":     search,
					"Total":      0,
					"error":      "Kategori tidak ditemukan",
				})
			} else {
				ctx.HTML(http.StatusInternalServerError, "categories_admin.html", gin.H{
					"Categories": []Categories{},
					"Pages":      []int{},
					"Page":       page,
					"Search":     search,
					"Total":      0,
					"error":      "Terjadi kesalahan: " + err.Error(),
				})
			}
			return
		}

		ctx.HTML(http.StatusOK, "update_categories.html", gin.H{
			"Categories": cat,
			"Page":       page,
			"search":     search,
		})
	})

	app.POST("/categories/update/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		name := ctx.PostForm("name")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		if strings.TrimSpace(name) == "" {
			ctx.HTML(http.StatusBadRequest, "update_categories.html", gin.H{
				"error": "Nama kategori wajib diisi",
			})
			return
		}

		result, err := db.Exec("UPDATE categories SET name = ? WHERE id = ? ", name, id)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "update_categories.html", gin.H{
				"error": "Terjadi kesalahan: " + err.Error(),
			})
			return
		}
		rows, err := result.RowsAffected()
		if err != nil || rows == 0 {
			ctx.HTML(http.StatusInternalServerError, "update_categories.html", gin.H{
				"error": "Gagal memperbarui kategori, coba lagi",
			})
			return
		}
		ctx.Redirect(http.StatusFound, "/categories?page="+page+"&search="+search)
	})

	app.POST("/categories/delete/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		page := ctx.Query("page")
		search := ctx.Query("search")

		result, err := db.Exec("DELETE FROM categories WHERE id=?", id)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "categories_admin.html", gin.H{
				"error": "Gagal menghapus kategori: " + err.Error(),
			})
			return
		}
		row, err := result.RowsAffected()
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "categories_admin.html", gin.H{
				"error": "Terjadi kesalahan saat memproses penghapusan",
			})
			return
		}
		if row == 0 {
			ctx.HTML(http.StatusBadRequest, "categories_admin.html", gin.H{
				"error": "Kategori tidak ditemukan atau sudah dihapus",
			})
			return
		}

		ctx.Redirect(http.StatusFound, "/categories?page="+page+"&search="+search)
	})

	// =================== Users ===================

	app.GET("/user", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		search := ctx.DefaultQuery("search", "")
		status := ctx.DefaultQuery("status", "all")
		page, err := strconv.Atoi(ctx.Query("page"))
		formatSearch := "%" + search + "%"
		if err != nil || page < 1 {
			page = 1
		}

		limit := 7
		offset := (page - 1) * limit

		// ============================================
		//  karena sama dan butuh percabangan status
		// ============================================
		baseQuery := " FROM users AS u WHERE (u.name LIKE ? OR u.email LIKE ?)"
		if status != "all" {
			if status == "active" {
				baseQuery += ` AND is_active = 1`
			} else {
				baseQuery += ` AND is_active = 0`
			}
		}
		// ============================================

		query := "SELECT u.id, u.name, u.email, u.is_active, role " + baseQuery + " LIMIT ? OFFSET ?"

		row, err := db.Query(query, formatSearch, formatSearch, limit, offset)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "user_admin.html", gin.H{
				"User":   []User{},
				"Count":  CountsUser{},
				"Search": search,
				"Status": status,
				"Pages":  []int{},
				"Page":   page,
				"error":  "Gagal mengambil data user: " + err.Error(),
			})
			return
		}

		var user []User
		i := offset + 1
		for row.Next() {
			var us User
			if err := row.Scan(&us.ID, &us.Name, &us.Email, &us.IsActive, &us.Role); err != nil {
				ctx.HTML(http.StatusInternalServerError, "user_admin.html", gin.H{
					"User":   []User{},
					"Count":  CountsUser{},
					"Search": search,
					"Status": status,
					"Pages":  []int{},
					"Page":   page,
					"error":  "Gagal membaca data user: " + err.Error(),
				})
				return
			}
			us.Index = i
			i++
			user = append(user, us)
		}

		userCount := "SELECT " +
			"Count(*) as total_user," +
			"Count(CASE WHEN u.is_active = 1 THEN 1 END) as total_active," +
			"Count(CASE WHEN u.is_active = 0 THEN 1 END) as total_inactive" +
			baseQuery

		var count CountsUser
		err = db.QueryRow(userCount, formatSearch, formatSearch).Scan(&count.CountUser, &count.CountActive, &count.CountNonactive)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "user_admin.html", gin.H{
				"User":   []User{},
				"Count":  CountsUser{},
				"Search": search,
				"Status": status,
				"Pages":  []int{},
				"Page":   page,
				"error":  "Gagal menghitung total user: " + err.Error(),
			})
			return
		}

		totalPage := int(math.Ceil(float64(count.CountUser) / float64(limit)))
		if page > totalPage && totalPage != 0 {
			ctx.Redirect(http.StatusFound, fmt.Sprintf("/user?page=%d&search=%s&status=%s", totalPage, url.QueryEscape(search), status))
		}
		pages := make([]int, totalPage)
		for i := 0; i < totalPage; i++ {
			pages[i] = i + 1
		}

		ctx.HTML(http.StatusOK, "user_admin.html", gin.H{
			"User":   user,
			"Count":  count,
			"Search": search,
			"Status": status,
			"Index":  i,
			"Pages":  pages,
			"Page":   page,
		})

	})

	app.GET("/user/create", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		page := ctx.Query("page")
		search := ctx.Query("search")

		ctx.HTML(http.StatusOK, "create_user.html", gin.H{
			"Page":   page,
			"Search": search,
		})
	})

	app.POST("/user/create", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		name := ctx.PostForm("name")
		email := ctx.PostForm("email")
		password := ctx.PostForm("password")
		role := ctx.PostForm("role")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		if name == "" || email == "" || password == "" || role == "" {
			ctx.HTML(http.StatusBadRequest, "create_user.html", gin.H{
				"error":  "Semua field wajib diisi",
				"Name":   name,
				"Email":  email,
				"Role":   role,
				"Page":   page,
				"Search": search,
			})
			return
		}

		emailRegex := regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)

		if !emailRegex.MatchString(email) {
			ctx.HTML(http.StatusBadRequest, "create_user.html", gin.H{
				"error":  "Format email tidak valid",
				"Name":   name,
				"Email":  email,
				"Role":   role,
				"Page":   page,
				"Search": search,
			})
			return
		}

		if len(password) < 6 {
			ctx.HTML(http.StatusBadRequest, "create_user.html", gin.H{
				"error":  "Password minimal 6 karakter",
				"Name":   name,
				"Email":  email,
				"Role":   role,
				"Page":   page,
				"Search": search,
			})
			return
		}

		hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_user.html", gin.H{
				"error":  "Terjadi kesalahan saat memproses password",
				"Name":   name,
				"Email":  email,
				"Role":   role,
				"Page":   page,
				"Search": search,
			})
			return
		}

		result, err := db.Exec("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)", name, email, string(hashedPass), role)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_user.html", gin.H{
				"error":  "Gagal membuat user: " + err.Error(),
				"Name":   name,
				"Email":  email,
				"Role":   role,
				"Page":   page,
				"Search": search,
			})
			return
		}

		row, err := result.RowsAffected()
		if err != nil || row == 0 {
			ctx.HTML(http.StatusInternalServerError, "create_user.html", gin.H{
				"error":  "Gagal membuat user, coba lagi",
				"Name":   name,
				"Email":  email,
				"Role":   role,
				"Page":   page,
				"Search": search,
			})
			return
		}
		ctx.Redirect(http.StatusFound, "/user?page="+page+"&search="+search)
	})

	app.POST("/user/update/status/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		status := ctx.PostForm("status")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		fmt.Println(id, status)

		var is_active int
		if status == "active" {
			is_active = 1
		} else {
			is_active = 0
		}

		result, err := db.Exec("UPDATE users SET is_active = ? WHERE id = ?", is_active, id)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "user_admin.html", gin.H{
				"error": "Gagal memperbarui status user: " + err.Error(),
			})
			return
		}
		row, err := result.RowsAffected()
		if err != nil || row == 0 {
			ctx.HTML(http.StatusInternalServerError, "user_admin.html", gin.H{
				"error": "Gagal memperbarui status user, coba lagi",
			})
			return
		}

		ctx.Redirect(http.StatusFound, "/user?page="+page+"&search="+search)
	})

	app.GET("/user/update/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		page := ctx.Query("page")
		search := ctx.Query("search")

		var user User

		err := db.QueryRow("SELECT id,name,email,role FROM users WHERE id = ?", id).Scan(&user.ID, &user.Name, &user.Email, &user.Role)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.HTML(http.StatusNotFound, "user_admin.html", gin.H{
					"User":   nil,
					"Page":   page,
					"Search": search,
					"error":  "User tidak ditemukan",
				})
				return
			}
			ctx.HTML(http.StatusInternalServerError, "user_admin.html", gin.H{
				"User":   nil,
				"Page":   page,
				"Search": search,
				"error":  "Terjadi kesalahan: " + err.Error(),
			})
			return
		}

		ctx.HTML(http.StatusOK, "update_user.html", gin.H{
			"User":   user,
			"Page":   page,
			"Search": search,
		})
	})

	app.POST("/user/update/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		name := ctx.PostForm("name")
		email := ctx.PostForm("email")
		password := ctx.PostForm("password")
		role := ctx.PostForm("role")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		emailRegex := regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)

		if !emailRegex.MatchString(email) {
			ctx.HTML(http.StatusBadRequest, "update_user.html", gin.H{
				"error": "Format email tidak valid",
			})
			return
		}

		if password != "" {
			newHashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "update_user.html", gin.H{
					"error": "Gagal mengenkripsi password: " + err.Error(),
				})
				return
			}

			result, err := db.Exec("UPDATE users SET name = ? , email = ?, password = ?, role = ? WHERE id = ?", name, email, newHashedPass, role, id)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "update_user.html", gin.H{
					"error": "Gagal memperbarui user: " + err.Error(),
				})
				return
			}
			row, err := result.RowsAffected()
			if err != nil || row == 0 {
				ctx.HTML(http.StatusInternalServerError, "update_user.html", gin.H{
					"error": "Gagal memperbarui user, coba lagi",
				})
				return
			}
		} else {
			result, err := db.Exec("UPDATE users SET name = ? , email = ?, role = ? WHERE id = ?", name, email, role, id)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "update_user.html", gin.H{
					"error": "Gagal memperbarui user: " + err.Error(),
				})
				return
			}
			row, err := result.RowsAffected()
			if err != nil || row == 0 {
				ctx.HTML(http.StatusInternalServerError, "update_user.html", gin.H{
					"error": "Gagal memperbarui user, coba lagi",
				})
				return
			}

			ctx.Redirect(http.StatusFound, "/user?page="+page+"&search="+search)
		}
	})
	// ============================= Books ==============================
	app.GET("/book", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		search := ctx.DefaultQuery("search", "")
		status := ctx.DefaultQuery("status", "all")
		category := ctx.DefaultQuery("category", "all")
		var books []Book
		var categories []Categories

		page, err := strconv.Atoi(ctx.Query("page"))
		if err != nil || page < 1 {
			page = 1
		}

		limit := 14
		offset := (page - 1) * limit

		query := `
        SELECT b.id, b.title, b.isbn, b.category_id, b.img, c.name AS category_name,
        CAST(
            CASE 
                WHEN EXISTS(
                    SELECT 1 
                    FROM bookings AS bk
                    JOIN detail_bookings AS db ON db.booking_id = bk.id
                    WHERE db.book_id = b.id AND bk.actual_return_date IS NULL
                ) THEN 1 ELSE 0
            END AS UNSIGNED
        ) AS is_borrowed
        FROM books AS b
        JOIN categories AS c ON c.id = b.category_id
        WHERE (b.title LIKE ? OR b.isbn LIKE ?)
    `
		args := []interface{}{"%" + search + "%", "%" + search + "%"}

		if status != "all" {
			switch status {
			case "available":
				query += `
                AND NOT EXISTS(
                    SELECT 1 
                    FROM bookings AS bk 
                    JOIN detail_bookings AS db ON bk.id = db.booking_id
                    WHERE b.id = db.book_id AND bk.actual_return_date IS NULL
                )
            `
			case "borrowed":
				query += `
                AND EXISTS(
                    SELECT 1 
                    FROM bookings AS bk 
                    JOIN detail_bookings AS db ON bk.id = db.booking_id
                    WHERE b.id = db.book_id AND bk.actual_return_date IS NULL
                )
            `
			}
		}

		if category != "all" {
			query += ` AND b.category_id = ?`
			args = append(args, category)
		}

		query += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)

		row, err := db.Query(query, args...)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "book_admin.html", gin.H{
				"Book":             []Book{},
				"Search":           search,
				"Status":           status,
				"Category":         []Categories{},
				"SelectedCategory": category,
				"Count":            BooksCount{},
				"Pages":            []int{},
				"Page":             page,
				"error":            "Gagal mengambil data buku: " + err.Error(),
			})
			return
		}
		defer row.Close()

		i := offset + 1

		for row.Next() {
			var b Book
			if err := row.Scan(&b.ID, &b.Title, &b.Isbn, &b.CategoryId, &b.Img, &b.CategoryName, &b.IsBorrowed); err != nil {
				ctx.HTML(http.StatusInternalServerError, "book_admin.html", gin.H{
					"Book":             []Book{},
					"Search":           search,
					"Status":           status,
					"Category":         []Categories{},
					"SelectedCategory": category,
					"Count":            BooksCount{},
					"Pages":            []int{},
					"Page":             page,
					"error":            "Gagal membaca data buku: " + err.Error(),
				})
				return
			}
			b.Index = i
			i++
			books = append(books, b)
		}

		results, err := db.Query("SELECT id, name FROM categories")
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "book_admin.html", gin.H{
				"Book":             books,
				"Search":           search,
				"Status":           status,
				"Category":         []Categories{},
				"SelectedCategory": category,
				"Count":            BooksCount{},
				"Pages":            []int{},
				"Page":             page,
				"error":            "Gagal mengambil kategori: " + err.Error(),
			})
			return
		}
		defer results.Close()

		for results.Next() {
			var c Categories
			if err := results.Scan(&c.ID, &c.Name); err != nil {
				ctx.HTML(http.StatusInternalServerError, "book_admin.html", gin.H{
					"Book":             books,
					"Search":           search,
					"Status":           status,
					"Category":         categories,
					"SelectedCategory": category,
					"Count":            BooksCount{},
					"Pages":            []int{},
					"Page":             page,
					"error":            "Gagal membaca kategori: " + err.Error(),
				})
				return
			}
			categories = append(categories, c)
		}

		// ==========================
		//  COUNT FOR PAGINATION
		// ==========================
		countQuery := `
        SELECT COUNT(b.id)
        FROM books AS b
        JOIN categories AS c ON c.id = b.category_id
        WHERE (b.title LIKE ? OR b.isbn LIKE ?)
    `
		countArgs := []interface{}{"%" + search + "%", "%" + search + "%"}

		if status != "all" {
			switch status {
			case "available":
				countQuery += `
                AND NOT EXISTS(
                    SELECT 1
                    FROM bookings AS bk
                    JOIN detail_bookings AS db ON db.booking_id = bk.id
                    WHERE b.id = db.book_id AND bk.actual_return_date IS NULL
                )
            `
			case "borrowed":
				countQuery += `
                AND EXISTS(
                    SELECT 1
                    FROM bookings AS bk
                    JOIN detail_bookings AS db ON db.booking_id = bk.id
                    WHERE b.id = db.book_id AND bk.actual_return_date IS NULL
                )
            `
			}
		}

		if category != "all" {
			countQuery += " AND b.category_id = ?"
			countArgs = append(countArgs, category)
		}

		var totalItems int
		if err := db.QueryRow(countQuery, countArgs...).Scan(&totalItems); err != nil {
			ctx.HTML(http.StatusInternalServerError, "book_admin.html", gin.H{
				"Book":             books,
				"Search":           search,
				"Status":           status,
				"Category":         categories,
				"SelectedCategory": category,
				"Count":            BooksCount{},
				"Pages":            []int{},
				"Page":             page,
				"error":            "Gagal menghitung total buku: " + err.Error(),
			})
			return
		}

		totalPage := int(math.Ceil(float64(totalItems) / float64(limit)))
		if page > totalPage && totalPage != 0 {
			ctx.Redirect(http.StatusFound, fmt.Sprintf("bookings?page=%d&search=%s", totalPage, url.QueryEscape(search)))
			return
		}
		if totalPage < 1 {
			totalPage = 1
		}

		pages := make([]int, totalPage)
		for i := 0; i < totalPage; i++ {
			pages[i] = i + 1
		}

		// ==========================
		// 4. STATISTIK BUKU
		// =========================
		bookCount := `
        SELECT 
            COUNT(b.id),
            COALESCE(SUM(CASE 
                WHEN EXISTS(
                    SELECT 1 
                    FROM bookings AS bk
                    JOIN detail_bookings AS db ON bk.id = db.booking_id
                    WHERE db.book_id = b.id AND bk.actual_return_date IS NULL
                ) THEN 1 ELSE 0 END
            ), 0) AS borrowed,
            COALESCE(SUM(CASE 
                WHEN NOT EXISTS(
                    SELECT 1 
                    FROM bookings AS bk
                    JOIN detail_bookings AS db ON bk.id = db.booking_id
                    WHERE db.book_id = b.id AND bk.actual_return_date IS NULL
                ) THEN 1 ELSE 0 END
            ), 0) AS available
        FROM books AS b
        JOIN categories AS c ON c.id = b.category_id
        WHERE (b.title LIKE ? OR b.isbn LIKE ?)
    `

		var count BooksCount
		var scanErr error

		if category != "all" {
			bookCount += " AND b.category_id = ?"
			scanErr = db.QueryRow(bookCount, "%"+search+"%", "%"+search+"%", category).
				Scan(&count.BookCount, &count.BookBorrowed, &count.BookAvailable)
		} else {
			scanErr = db.QueryRow(bookCount, "%"+search+"%", "%"+search+"%").
				Scan(&count.BookCount, &count.BookBorrowed, &count.BookAvailable)
		}

		if scanErr != nil {
			ctx.HTML(http.StatusInternalServerError, "book_admin.html", gin.H{
				"Book":             books,
				"Search":           search,
				"Status":           status,
				"Category":         categories,
				"SelectedCategory": category,
				"Count":            BooksCount{},
				"Pages":            pages,
				"Page":             page,
				"error":            "Gagal menghitung statistik buku: " + scanErr.Error(),
			})
			return
		}

		ctx.HTML(http.StatusOK, "book_admin.html", gin.H{
			"Book":             books,
			"Search":           search,
			"Status":           status,
			"Category":         categories,
			"SelectedCategory": category,
			"Count":            count,
			"Pages":            pages,
			"Page":             page,
		})
	})

	app.GET("/book/create", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		page := ctx.Query("page")
		search := ctx.Query("search")

		rows, err := db.Query("SELECT id, name FROM categories")
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_book.html", gin.H{
				"error": "Terjadi kesalahan saat mengambil kategori: " + err.Error(),
			})
			return
		}

		var categories []Categories
		for rows.Next() {
			var cat Categories
			if err := rows.Scan(&cat.ID, &cat.Name); err != nil {
				ctx.HTML(http.StatusInternalServerError, "create_book.html", gin.H{
					"error": "Terjadi kesalahan saat memproses kategori: " + err.Error(),
				})
				return
			}
			categories = append(categories, cat)
		}
		ctx.HTML(http.StatusOK, "create_book.html", gin.H{
			"Categories": categories,
			"Page":       page,
			"Search":     search,
		})
	})

	app.POST("/book/create", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		title := ctx.PostForm("title")
		isbn := ctx.PostForm("isbn")
		category_id := ctx.PostForm("category_id")
		img := ctx.PostForm("img")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		if title == "" || isbn == "" || category_id == "" || img == "" {
			ctx.HTML(http.StatusBadRequest, "create_book.html", gin.H{
				"error": "Semua kolom harus diisi",
			})
			return
		}

		result, err := db.Exec("INSERT INTO books (title,isbn,category_id,img) VALUES (?,?,?,?)", title, isbn, category_id, img)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_book.html", gin.H{
				"error": "Terjadi kesalahan: " + err.Error(),
			})
		}
		row, err := result.RowsAffected()
		if err != nil || row == 0 {
			ctx.HTML(http.StatusInternalServerError, "create_book.html", gin.H{
				"error": "Gagal membuat buku",
			})
			return
		}

		ctx.Redirect(http.StatusFound, "/book?page="+page+"&search="+search)
	})

	app.GET("/book/update/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		page := ctx.Query("page")
		search := ctx.Query("search")

		var book Book
		err := db.QueryRow("SELECT id, title, isbn, category_id, img FROM books WHERE id = ?", id).Scan(&book.ID, &book.Title, &book.Isbn, &book.CategoryId, &book.Img)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.HTML(http.StatusNotFound, "update_book.html", gin.H{
					"error": "Buku tidak ditemukan",
				})
			}
			ctx.HTML(http.StatusInternalServerError, "update_book.html", gin.H{
				"error": "Terjadi kesalahan: " + err.Error(),
			})
		}

		row, err := db.Query("SELECT id, name FROM categories")
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "update_book.html", gin.H{
				"error": "Terjadi kesalahan: " + err.Error(),
			})
		}

		var categories []Categories
		for row.Next() {
			var cat Categories
			if err := row.Scan(&cat.ID, &cat.Name); err != nil {
				ctx.HTML(http.StatusInternalServerError, "update_book.html", gin.H{
					"error": "Terjadi kesalahan: " + err.Error(),
				})
			}
			categories = append(categories, cat)
		}

		ctx.HTML(http.StatusOK, "update_book.html", gin.H{
			"Book":       book,
			"Categories": categories,
			"Page":       page,
			"Search":     search,
		})
	})

	app.POST("/book/update/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		title := ctx.PostForm("title")
		isbn := ctx.PostForm("isbn")
		category_id := ctx.PostForm("category_id")
		img := ctx.PostForm("img")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		if title == "" || isbn == "" || category_id == "" || img == "" {
			ctx.HTML(http.StatusBadRequest, "update_book.html", gin.H{
				"error": "Semua kolom harus diisi",
			})
			return
		}

		result, err := db.Exec("UPDATE books SET title = ?, isbn = ?, category_id = ?, img = ? WHERE id = ?", title, isbn, category_id, img, id)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "update_book.html", gin.H{
				"error": "Terjadi kesalahan: " + err.Error(),
			})
			return
		}
		row, err := result.RowsAffected()
		if err != nil || row == 0 {
			ctx.HTML(http.StatusInternalServerError, "update_book.html", gin.H{
				"error": "Gagal memperbarui buku",
			})
			return
		}
		ctx.Redirect(http.StatusFound, "/book?page="+page+"&search="+search)
	})

	app.POST("/book/delete/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		result, err := db.Exec("DELETE FROM books WHERE id = ?", id)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "book_admin.html", gin.H{
				"error": "Terjadi kesalahan: " + err.Error(),
			})
			return
		}

		row, err := result.RowsAffected()
		if err != nil || row == 0 {
			ctx.HTML(http.StatusInternalServerError, "book_admin.html", gin.H{
				"error": "Gagal menghapus buku",
			})
			return
		}

		ctx.Redirect(http.StatusFound, "/book?page="+page+"&search="+search)
	})

	// ============================== Bookings ==========================

	app.GET("/bookings", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		search := ctx.DefaultQuery("search", "")
		filter := ctx.DefaultQuery("filter", "all")
		page, err := strconv.Atoi(ctx.Query("page"))
		formatSearch := "%" + search + "%"
		if err != nil || page < 1 {
			page = 1
		}
		limit := 8
		offset := (page - 1) * limit

		switch filter {
		case "user":
			queryUser := `
				SELECT DISTINCT u.id, u.name
				FROM users AS u
				JOIN bookings AS bk ON bk.user_id = u.id
				WHERE u.name LIKE ?
				ORDER BY u.id ASC
				LIMIT ? OFFSET ?`
			countsUser := `
				SELECT COUNT(DISTINCT u.id)
				FROM users AS u
				JOIN bookings AS bk ON bk.user_id = u.id
				WHERE u.name LIKE ?
			`

			rows, err := db.Query(queryUser, formatSearch, limit, offset)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "bookings_user.html", gin.H{
					"error": "Gagal mengambil data user",
				})
				return
			}
			defer rows.Close()

			var users []User
			i := offset + 1
			for rows.Next() {
				var u User
				if err := rows.Scan(&u.ID, &u.Name); err != nil {
					ctx.HTML(http.StatusInternalServerError, "bookings_user.html", gin.H{
						"error": "Gagal memproses data user",
					})
					return
				}
				u.Index = i
				i++
				users = append(users, u)
			}

			var count CountsUser
			err = db.QueryRow(countsUser, formatSearch).Scan(&count.CountUser)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "bookings_user.html", gin.H{
					"error": "Gagal menghitung data user",
				})
				return
			}

			totalPage := int(math.Ceil(float64(count.CountUser) / float64(limit)))
			if page > totalPage && totalPage != 0 {
				ctx.Redirect(http.StatusFound, fmt.Sprintf("bookings?page=%d&search=%s", totalPage, url.QueryEscape(search)))
				return
			}
			pages := make([]int, totalPage)
			for i := 0; i < totalPage; i++ {
				pages[i] = i + 1
			}

			ctx.HTML(http.StatusOK, "bookings_user.html", gin.H{
				"User":             users,
				"Count":            count,
				"Pages":            pages,
				"SelectedCategory": filter,
				"Page":             page,
				"Search":           search,
			})

		case "book":
			queryBook := `
			SELECT DISTINCT b.id, b.title
			FROM books AS b
			JOIN detail_bookings AS db ON db.book_id = b.id
			WHERE b.title LIKE ?
			ORDER BY b.id ASC
			LIMIT ? OFFSET ?
				`
			countBook := `
				SELECT COUNT(DISTINCT b.id)
				FROM books AS b
				JOIN detail_bookings AS db ON db.book_id = b.id
				WHERE b.title LIKE ?
			`

			rows, err := db.Query(queryBook, formatSearch, limit, offset)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "bookings_book.html", gin.H{
					"error": "Gagal mengambil data buku",
				})
				return
			}
			defer rows.Close()

			var books []Book
			i := offset + 1
			for rows.Next() {
				var b Book
				if err := rows.Scan(&b.ID, &b.Title); err != nil {
					ctx.HTML(http.StatusInternalServerError, "bookings_book.html", gin.H{
						"error": "Gagal memproses data buku",
					})
					return
				}
				b.Index = i
				i++
				books = append(books, b)
			}

			var count BooksCount
			err = db.QueryRow(countBook, formatSearch).Scan(&count.BookCount)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "bookings_book.html", gin.H{
					"error": "Gagal menghitung data buku",
				})
				return
			}

			totalPage := int(math.Ceil(float64(count.BookCount) / float64(limit)))
			if page > totalPage && totalPage != 0 {
				ctx.Redirect(http.StatusFound, fmt.Sprintf("bookings?page=%d&search=%s", totalPage, url.QueryEscape(search)))
				return
			}
			pages := make([]int, totalPage)
			for i := 0; i < totalPage; i++ {
				pages[i] = i + 1
			}

			ctx.HTML(http.StatusOK, "bookings_book.html", gin.H{
				"Book":             books,
				"Count":            count,
				"Pages":            pages,
				"SelectedCategory": filter,
				"Page":             page,
				"Search":           search,
			})

		default:
			query := `
				SELECT bk.id,
					   u.name AS user_name,
					   GROUP_CONCAT(b.title SEPARATOR ", ") AS book_titles,
					   bk.start_date,
					   bk.end_date,
					   bk.actual_return_date
				FROM bookings AS bk
				JOIN users AS u ON u.id = bk.user_id
				JOIN detail_bookings AS db ON bk.id = db.booking_id
				JOIN books AS b ON b.id = db.book_id
				WHERE bk.actual_return_date is NULL
				AND (u.name LIKE ? OR b.title LIKE ?)
				GROUP BY bk.id, u.name, bk.start_date, bk.end_date, bk.actual_return_date
				LIMIT ? OFFSET ?`
			argsQuery := []interface{}{formatSearch, formatSearch, limit, offset}

			countBookings := `
				SELECT COUNT(DISTINCT bk.id)
				FROM bookings AS bk
				JOIN users AS u ON u.id = bk.user_id
				JOIN detail_bookings AS db ON bk.id = db.booking_id
				JOIN books AS b ON b.id = db.book_id
				WHERE bk.actual_return_date is NULL
				AND (u.name LIKE ? OR b.title LIKE ?)
			`

			rows, err := db.Query(query, argsQuery...)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "bookings.html", gin.H{
					"error": "Gagal mengambil data booking",
				})
				return
			}
			defer rows.Close()

			var bookings []BookingDetail
			i := offset + 1
			location, _ := time.LoadLocation("Asia/Jakarta")
			for rows.Next() {
				var bo BookingDetail
				if err := rows.Scan(&bo.ID, &bo.UserName, &bo.BookTitles, &bo.StartDate, &bo.EndDate, &bo.ActualReturnDate); err != nil {
					ctx.HTML(http.StatusInternalServerError, "bookings.html", gin.H{
						"error": "Gagal memproses data booking",
					})
					return
				}
				bo.StartStr = bo.StartDate.In(location).Format("02 January 2006")
				bo.EndStr = bo.EndDate.In(location).Format("02 January 2006")
				if bo.ActualReturnDate.Valid {
					bo.ActualReturnStr = bo.ActualReturnDate.Time.In(location).Format("02 January 2006")
				}
				bo.Index = i
				i++
				bookings = append(bookings, bo)
			}

			var count BookingCount
			err = db.QueryRow(countBookings, formatSearch, formatSearch).Scan(&count.BookingCount)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "bookings.html", gin.H{
					"error": "Gagal menghitung data booking",
				})
				return
			}

			totalPage := int(math.Ceil(float64(count.BookingCount) / float64(limit)))
			if page > totalPage && totalPage != 0 {
				ctx.Redirect(http.StatusFound, fmt.Sprintf("bookings?page=%d&search=%s", totalPage, url.QueryEscape(search)))
				return
			}

			pages := make([]int, totalPage)
			for i := 0; i < totalPage; i++ {
				pages[i] = i + 1
			}

			ctx.HTML(http.StatusOK, "bookings.html", gin.H{
				"Bookings":         bookings,
				"Count":            count,
				"Pages":            pages,
				"SelectedCategory": filter,
				"Page":             page,
				"Search":           search,
			})
		}
	})

	app.GET("/bookings/create", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		page := ctx.Query("page")
		search := ctx.Query("search")

		queryUser := `
			SELECT u.id,
				   u.name,
			       u.is_active,
				   (
				   	 SELECT COUNT(db.booking_id) FROM bookings AS bk
					 JOIN detail_bookings AS db ON db.booking_id = bk.id
				     WHERE bk.user_id = u.id
						AND bk.start_date <= NOW()
						AND bk.actual_return_date IS NULL
				   ) AS is_borrowed
			FROM users AS u
			WHERE u.is_active = 1 and u.role = 'user'
			ORDER BY u.name ASC`
		queryBook := `
			SELECT b.id, b.title,
				EXISTS(
					SELECT 1 FROM bookings AS bk
					   JOIN detail_bookings AS db ON db.booking_id = bk.id
					   WHERE db.book_id = b.id
						 AND bk.start_date <= NOW()
						 AND bk.actual_return_date IS NULL
					) AS is_borrowed
			FROM books AS b
			ORDER BY b.title ASC`

		rowsUser, err := db.Query(queryUser)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
				"error": "Gagal mengambil data user",
			})
			return
		}
		defer rowsUser.Close()

		var users []User
		for rowsUser.Next() {
			var u User
			if err := rowsUser.Scan(&u.ID, &u.Name, &u.IsActive, &u.IsBorrowed); err != nil {
				ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
					"error": "Gagal memproses data user",
				})
				return
			}
			users = append(users, u)
		}

		rowsBook, err := db.Query(queryBook)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
				"error": "Gagal mengambil data buku",
			})
			return
		}
		defer rowsBook.Close()

		var books []Book
		for rowsBook.Next() {
			var b Book
			if err := rowsBook.Scan(&b.ID, &b.Title, &b.IsBorrowed); err != nil {
				ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
					"error": "Gagal memproses data buku",
				})
				return
			}
			books = append(books, b)
		}

		location, _ := time.LoadLocation("Asia/Jakarta")
		now := time.Now().In(location)
		date := BookingDetail{
			StartStr: now.Format("02 January 2006"),
			EndStr:   now.AddDate(0, 0, 7).Format("02 January 2006"),
		}

		ctx.HTML(http.StatusOK, "create_bookings.html", gin.H{
			"User":   users,
			"Book":   books,
			"Date":   date,
			"Page":   page,
			"Search": search,
		})
	})

	app.POST("/bookings/create", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		userIDStr := ctx.PostForm("user_id")
		bookIDsStr := ctx.PostFormArray("book_id[]")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		if userIDStr == "" {
			ctx.HTML(http.StatusBadRequest, "create_bookings.html", gin.H{
				"error": "Silakan pilih user",
			})
			return
		}

		if len(bookIDsStr) == 0 {
			ctx.HTML(http.StatusBadRequest, "create_bookings.html", gin.H{
				"error": "Pilih minimal satu buku",
			})
			return
		}

		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			ctx.HTML(http.StatusBadRequest, "create_bookings.html", gin.H{
				"error": "User tidak valid",
			})
			return
		}

		bookIDs := []int{}
		for _, bid := range bookIDsStr {
			id, err := strconv.Atoi(bid)
			if err != nil {
				ctx.HTML(http.StatusBadRequest, "create_bookings.html", gin.H{
					"error": "ID buku tidak valid",
				})
				return
			}
			bookIDs = append(bookIDs, id)
		}

		var activeBorrows int
		err = db.QueryRow(`
			SELECT COUNT(db.booking_id) 
			FROM bookings AS bk
			JOIN detail_bookings AS db ON db.booking_id = bk.id
			WHERE user_id = ?
				AND start_date <= NOW()
				AND actual_return_date IS NULL
		`, userID).Scan(&activeBorrows)

		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
				"error": "Gagal mengecek peminjaman user",
			})
			return
		}

		if activeBorrows+len(bookIDs) > 2 {
			ctx.HTML(http.StatusBadRequest, "create_bookings.html", gin.H{
				"error": "User tidak boleh meminjam lebih dari 2 buku",
			})
			return
		}

		location, _ := time.LoadLocation("Asia/Jakarta")
		startDate := time.Now().In(location)
		endDate := startDate.AddDate(0, 0, 7)

		result, err := db.Exec("INSERT INTO bookings (user_id, start_date, end_date) VALUES (?, ?, ?)", userID, startDate, endDate)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
				"error": "Gagal membuat booking",
			})
			return
		}

		row, err := result.RowsAffected()
		if err != nil || row == 0 {
			ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
				"error": "Booking tidak tersimpan",
			})
			return
		}

		bookingID, err := result.LastInsertId()
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
				"error": "Gagal mendapatkan ID booking",
			})
			return
		}

		for _, bookID := range bookIDs {
			result, err := db.Exec("INSERT INTO detail_bookings (book_id, booking_id) VALUES (?, ?)", bookID, bookingID)
			if err != nil {
				ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
					"error": "Gagal menyimpan detail booking",
				})
				return
			}
			row, err := result.RowsAffected()
			if err != nil || row == 0 {
				ctx.HTML(http.StatusInternalServerError, "create_bookings.html", gin.H{
					"error": "Detail booking gagal disimpan",
				})
				return
			}
		}

		ctx.Redirect(http.StatusSeeOther, "/bookings?page="+page+"&search="+search)
	})

	app.GET("/bookings/return/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id := ctx.Param("id")
		page := ctx.Query("page")
		search := ctx.Query("search")

		query := `
			SELECT 
				bk.id AS booking_id,
				u.name AS user_name,
				bk.start_date,
				bk.end_date,
				bk.actual_return_date,
				GROUP_CONCAT(b.title SEPARATOR ", ") AS book_titles
			FROM bookings AS bk
			JOIN users AS u ON u.id = bk.user_id
			JOIN detail_bookings AS db ON db.booking_id = bk.id
			JOIN books AS b ON b.id = db.book_id
			WHERE bk.id = ?
			GROUP BY bk.id, u.name, bk.start_date, bk.end_date, bk.actual_return_date
		`

		var bo BookingDetail
		err := db.QueryRow(query, id).Scan(&bo.ID, &bo.UserName, &bo.StartDate, &bo.EndDate, &bo.ActualReturnDate, &bo.BookTitles)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.HTML(http.StatusNotFound, "return_bookings.html", gin.H{
					"error": "Data booking tidak ditemukan",
				})
				return
			}

			ctx.HTML(http.StatusInternalServerError, "return_bookings.html", gin.H{
				"error": "Gagal mengambil data booking",
			})
			return
		}

		location, _ := time.LoadLocation("Asia/Jakarta")
		now := time.Now().In(location)

		bo.StartStr = bo.StartDate.In(location).Format("02 January 2006")
		bo.EndStr = bo.EndDate.In(location).Format("02 January 2006")
		bo.ActualReturnStr = now.Format("02 January 2006")

		var fee float64
		err = db.QueryRow("SELECT penalty_fee FROM settings LIMIT 1").Scan(&fee)
		if err == sql.ErrNoRows {
			fee = 0
		} else if err != nil {
			ctx.HTML(http.StatusInternalServerError, "return_bookings.html", gin.H{
				"error": "Gagal mengambil data denda",
			})
			return
		}

		overdue := int(now.Sub(bo.EndDate).Hours() / 24)
		if overdue < 0 {
			overdue = 0
		}

		penalty := float64(overdue) * fee

		ctx.HTML(200, "return_bookings.html", gin.H{
			"Bookings": bo,
			"Penalty":  penalty,
			"Page":     page,
			"Search":   search,
		})
	})

	app.POST("/bookings/return/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		bookingID := ctx.Param("id")
		penalty := ctx.PostForm("penalty")
		page := ctx.PostForm("page")
		search := ctx.PostForm("search")

		if bookingID == "" {
			ctx.HTML(http.StatusBadRequest, "return_bookings.html", gin.H{
				"error": "ID booking tidak valid",
			})
			return
		}

		if penalty == "" {
			penalty = "0"
		}

		location, _ := time.LoadLocation("Asia/Jakarta")
		now := time.Now().In(location)

		result, err := db.Exec(`
				UPDATE bookings 
				SET actual_return_date = ?, penalty_fee = ?
				WHERE id = ?
			`, now, penalty, bookingID)

		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "return_bookings.html", gin.H{
				"error": err.Error(),
			})
			return
		}
		row, err := result.RowsAffected()
		if err != nil || row == 0 {
			ctx.HTML(http.StatusInternalServerError, "return_bookings.html", gin.H{
				"error": "Gagal mengembalikan buku",
			})
			return
		}
		redirectURL := "/bookings"
		if page != "" || search != "" {
			redirectURL = "/bookings?page=" + page + "&search=" + search
		}

		ctx.Redirect(http.StatusFound, redirectURL)
	})

	app.GET("/bookings_user/detail/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id, _ := strconv.Atoi(ctx.Param("id"))
		search := ctx.DefaultQuery("search", "")
		formatSearch := "%" + search + "%"

		page, err := strconv.Atoi(ctx.Query("page"))
		if err != nil || page < 1 {
			page = 1
		}

		limit := 9
		offset := (page - 1) * limit

		query := `
			SELECT
				bk.id,
				GROUP_CONCAT(b.title SEPARATOR ", ") AS book_titles,
				COUNT(db.book_id) AS total_books,
				bk.start_date,
				bk.end_date,
				bk.actual_return_date
			FROM bookings bk
			JOIN detail_bookings db ON db.booking_id = bk.id
			JOIN books b ON b.id = db.book_id
			WHERE bk.user_id = ? AND b.title LIKE ?
			GROUP BY bk.id
			ORDER BY bk.start_date ASC
			LIMIT ? OFFSET ?
		`

		queryCount := `
			SELECT COUNT(DISTINCT bk.id)
			FROM bookings bk
			JOIN detail_bookings db ON db.booking_id = bk.id
			JOIN books b ON b.id = db.book_id
			WHERE bk.user_id = ? AND b.title LIKE ?
		`

		rows, err := db.Query(query, id, formatSearch, limit, offset)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "detail_user_admin.html", gin.H{
				"error": err.Error(),
			})
			return
		}
		defer rows.Close()

		var bookings []*BookingDetail
		i := offset + 1
		location, _ := time.LoadLocation("Asia/Jakarta")

		for rows.Next() {
			bo := &BookingDetail{}
			if err := rows.Scan(
				&bo.ID,
				&bo.BookTitles,
				&bo.TotalBooks,
				&bo.StartDate,
				&bo.EndDate,
				&bo.ActualReturnDate,
			); err != nil {
				ctx.HTML(http.StatusInternalServerError, "detail_user_admin.html", gin.H{
					"error": err.Error(),
				})
				return
			}

			bo.StartStr = bo.StartDate.In(location).Format("02 January 2006")
			bo.EndStr = bo.EndDate.In(location).Format("02 January 2006")
			if bo.ActualReturnDate.Valid {
				bo.ActualReturnStr = bo.ActualReturnDate.Time.In(location).Format("02 January 2006")
			} else {
				bo.ActualReturnStr = "-"
			}

			bo.Index = i
			i++
			bookings = append(bookings, bo)
		}

		if len(bookings) == 0 {
			ctx.HTML(http.StatusNotFound, "detail_user_admin.html", gin.H{
				"error": "Data peminjaman tidak ditemukan",
			})
			return
		}
		var count BookingCount
		err = db.QueryRow(queryCount, id, formatSearch).Scan(&count.BookingCount)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "detail_user_admin.html", gin.H{
				"error": err.Error(),
			})
			return
		}

		totalPage := int(math.Ceil(float64(count.BookingCount) / float64(limit)))
		pages := make([]int, totalPage)
		for i := 0; i < totalPage; i++ {
			pages[i] = i + 1
		}

		var totalBooks int
		queryTotalBooks := `
			SELECT COUNT(db.book_id)
			FROM bookings bk
			JOIN detail_bookings db ON db.booking_id = bk.id
			JOIN books b ON b.id = db.book_id
			WHERE bk.user_id = ? AND b.title LIKE ?
		`
		err = db.QueryRow(queryTotalBooks, id, formatSearch).Scan(&totalBooks)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "detail_user_admin.html", gin.H{
				"error": err.Error(),
			})
			return
		}

		var totalFines float64
		queryTotalFines := `
			SELECT COALESCE(SUM(penalty_fee), 0) FROM (
				SELECT DISTINCT bk.id, bk.penalty_fee
				FROM bookings bk
				JOIN detail_bookings db ON db.booking_id = bk.id
				JOIN books b ON b.id = db.book_id
				WHERE bk.user_id = ? AND b.title LIKE ?
			) as unique_bookings
		`
		err = db.QueryRow(queryTotalFines, id, formatSearch).Scan(&totalFines)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "detail_user_admin.html", gin.H{
				"error": err.Error(),
			})
			return
		}

		stats := gin.H{
			"TotalTransactions": count.BookingCount,
			"TotalBooks":        totalBooks,
			"TotalFines":        totalFines,
		}

		ctx.HTML(http.StatusOK, "detail_user_admin.html", gin.H{
			"Bookings": bookings,
			"Pages":    pages,
			"Page":     page,
			"Search":   search,
			"Count":    count,
			"Stats":    stats,
			"ID":       id,
		})
	})

	app.GET("/bookings_book/detail/:id", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		id, _ := strconv.Atoi(ctx.Param("id"))
		search := ctx.DefaultQuery("search", "")
		formatSearch := "%" + search + "%"

		page, _ := strconv.Atoi(ctx.Query("page"))
		if page < 1 {
			page = 1
		}
		limit := 10
		offset := (page - 1) * limit

		query := `
				SELECT
					bk.id,
					u.name,
					bk.start_date,
					bk.end_date,
					bk.actual_return_date
				FROM bookings bk
				JOIN users u ON u.id = bk.user_id
				JOIN detail_bookings db ON db.booking_id = bk.id
				WHERE db.book_id = ? AND u.name LIKE ?
				ORDER BY bk.start_date DESC
				LIMIT ? OFFSET ?
			`

		rows, err := db.Query(query, id, formatSearch, limit, offset)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "detail_book_admin.html", gin.H{
				"error": err.Error(),
			})
			return
		}
		defer rows.Close()

		var bookings []*BookingDetail
		index := offset + 1
		location, _ := time.LoadLocation("Asia/Jakarta")

		for rows.Next() {
			bo := &BookingDetail{}
			if err := rows.Scan(
				&bo.ID,
				&bo.UserName,
				&bo.StartDate,
				&bo.EndDate,
				&bo.ActualReturnDate,
			); err != nil {
				ctx.HTML(http.StatusInternalServerError, "detail_book_admin.html", gin.H{
					"error": err.Error(),
				})
				return
			}

			bo.StartStr = bo.StartDate.In(location).Format("02 January 2006")
			bo.EndStr = bo.EndDate.In(location).Format("02 January 2006")

			if bo.ActualReturnDate.Valid {
				bo.ActualReturnStr = bo.ActualReturnDate.Time.In(location).Format("02 January 2006")
			} else {
				bo.ActualReturnStr = "-"
			}

			bo.Index = index
			index++
			bookings = append(bookings, bo)
		}
		if len(bookings) == 0 {
			ctx.HTML(http.StatusNotFound, "detail_book_admin.html", gin.H{
				"error": "Data peminjaman untuk buku ini tidak ditemukan",
			})
			return
		}

		queryStats := `
				SELECT 
					COUNT(bk.id) as total_borrowed,
					COALESCE(SUM(bk.penalty_fee), 0) as total_fines
				FROM bookings bk
				JOIN users u ON u.id = bk.user_id
				JOIN detail_bookings db ON db.booking_id = bk.id
				WHERE db.book_id = ? AND u.name LIKE ?
			`

		var totalTransactions int
		var totalFines float64

		err = db.QueryRow(queryStats, id, formatSearch).Scan(&totalTransactions, &totalFines)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "detail_book_admin.html", gin.H{
				"error": err.Error(),
			})
			return
		}

		totalPage := int(math.Ceil(float64(totalTransactions) / float64(limit)))
		pages := make([]int, totalPage)
		for i := 0; i < totalPage; i++ {
			pages[i] = i + 1
		}

		stats := gin.H{
			"TotalTransactions": totalTransactions,
			"TotalFines":        totalFines,
		}

		ctx.HTML(http.StatusOK, "detail_book_admin.html", gin.H{
			"Bookings": bookings,
			"Pages":    pages,
			"Page":     page,
			"Search":   search,
			"Stats":    stats,
			"ID":       id,
		})
	})

	// =============================== Settings ==========================
	app.GET("/settings", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		var setting Settings
		err := db.QueryRow("SELECT penalty_fee FROM settings LIMIT 1").Scan(&setting.PenaltyFee)
		if err != nil {
			if err == sql.ErrNoRows {

				setting.PenaltyFee = 0.00
			} else {
				ctx.HTML(http.StatusInternalServerError, "settings_admin.html", gin.H{
					"Setting": setting,
					"error":   "Terjadi kesalahan saat mengambil pengaturan",
				})
				return
			}
		}

		ctx.HTML(http.StatusOK, "settings_admin.html", gin.H{
			"Setting": setting,
		})
	})

	app.POST("/settings/update", AuthMiddleware, AdminOnly, func(ctx *gin.Context) {
		feeStr := ctx.PostForm("penalty_fee")
		fee, err := strconv.ParseFloat(feeStr, 64)
		if err != nil || fee < 0 {
			ctx.HTML(http.StatusBadRequest, "settings_admin.html", gin.H{
				"Error": "Penalty fee tidak valid",
				"Setting": Settings{
					PenaltyFee: 0,
				},
			})
			return
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count)
		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Error": err.Error(),
			})
			return
		}

		if count > 0 {
			_, err = db.Exec("UPDATE settings SET penalty_fee = ?", fee)
		} else {
			_, err = db.Exec("INSERT INTO settings (penalty_fee) VALUES (?)", fee)
		}

		if err != nil {
			ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Error": err.Error(),
			})
			return
		}

		ctx.Redirect(http.StatusFound, "/settings")
	})

	// ============================== Home User ==========================
	app.GET("/home", AuthMiddleware, func(ctx *gin.Context) {
		search := ctx.Query("search")
		formatSearch := "%" + search + "%"
		var searchActive bool
		if search != "" {
			searchActive = true
		} else {
			searchActive = false
		}

		rows, err := db.Query(`
			SELECT DISTINCT c.id, c.name
			FROM categories AS c
			JOIN books AS b ON b.category_id = c.id
			ORDER BY name
		`)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		defer rows.Close()

		var categories []Categories
		for rows.Next() {
			var c Categories
			if err := rows.Scan(&c.ID, &c.Name); err != nil {
				ctx.String(http.StatusInternalServerError, err.Error())
				return
			}
			categories = append(categories, c)
		}

		queryBook := `
			SELECT 
				b.id, b.title, b.img, b.category_id,
				EXISTS(
					SELECT 1 FROM bookings AS bk
					JOIN detail_bookings AS db ON db.booking_id = bk.id
					WHERE db.book_id = b.id
						AND bk.start_date <= NOW()
						AND bk.end_date >= NOW()
						AND bk.actual_return_date IS NULL
				) AS is_borrowed
			FROM books AS b
			JOIN categories AS c ON c.id = b.category_id
			WHERE b.title LIKE ?
		`
		rows2, err := db.Query(queryBook, formatSearch)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		defer rows2.Close()

		var books []Book
		for rows2.Next() {
			var b Book
			if err := rows2.Scan(&b.ID, &b.Title, &b.Img, &b.CategoryId, &b.IsBorrowed); err != nil {
				ctx.String(http.StatusInternalServerError, err.Error())
				return
			}
			books = append(books, b)
		}

		bookCategory := make(map[int][]Book)
		for _, b := range books {
			bookCategory[b.CategoryId] = append(bookCategory[b.CategoryId], b)
		}

		ctx.HTML(http.StatusOK, "home_user.html", gin.H{
			"Categories":   categories,
			"Books":        books,
			"Search":       search,
			"BookCategory": bookCategory,
			"SearchActive": searchActive,
		})
	})

	app.GET("/all", AuthMiddleware, func(ctx *gin.Context) {
		categoryStr := ctx.Query("category")
		categoryID, _ := strconv.Atoi(categoryStr)
		search := ctx.Query("search")
		formatSearch := "%" + search + "%"
		page, _ := strconv.Atoi(ctx.Query("page"))
		if page < 1 {
			page = 1
		}
		limit := 8
		offset := (page - 1) * limit

		queryBook := `
			SELECT 
				b.id, b.title, b.img, b.category_id, c.name,
				EXISTS(
					SELECT 1 FROM bookings AS bk
					JOIN detail_bookings AS db ON db.booking_id = bk.id
					WHERE db.book_id = b.id
					AND bk.start_date <= NOW()
					AND bk.end_date >= NOW()
					AND bk.actual_return_date IS NULL
				) AS is_borrowed
			FROM books AS b
			JOIN categories AS c ON c.id = b.category_id
			WHERE c.id = ? 
			LIMIT ? OFFSET ?
		`

		rows, err := db.Query(queryBook, categoryID, limit, offset)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		defer rows.Close()

		var books []Book
		for rows.Next() {
			var b Book
			if err := rows.Scan(&b.ID, &b.Title, &b.Img, &b.CategoryId, &b.CategoryName, &b.IsBorrowed); err != nil {
				ctx.String(http.StatusInternalServerError, err.Error())
				return
			}
			books = append(books, b)
		}

		queryBookCategory := `
			SELECT COUNT(*) FROM books AS b
			JOIN categories AS c ON c.id = b.category_id
			WHERE c.id = ?
		`
		var count int
		if err = db.QueryRow(queryBookCategory, categoryID).Scan(&count); err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		totalPage := int(math.Ceil(float64(count) / float64(limit)))
		if page > totalPage && totalPage != 0 {
			ctx.Redirect(http.StatusFound, fmt.Sprintf("bookings?page=%d&search=%s", totalPage, formatSearch))
		}

		pages := make([]int, totalPage)
		for i := 0; i < totalPage; i++ {
			pages[i] = i + 1
		}

		ctx.HTML(http.StatusOK, "all_book_user.html", gin.H{
			"Books":      books,
			"Pages":      pages,
			"Page":       page,
			"Search":     search,
			"CategoryID": categoryID,
		})
	})

	app.GET("/view_detail_user/:id", AuthMiddleware, func(ctx *gin.Context) {
		id := ctx.Param("id")
		search := ctx.Query("search")
		categoryStr := ctx.Query("category")
		categoryID, _ := strconv.Atoi(categoryStr)
		fromHomeStr := ctx.Query("from_home")

		var fromHome bool
		if fromHomeStr == "true" {
			fromHome = true
		}
		queryDetail := `
		SELECT 
			b.id,
			b.title,
			b.isbn,
			b.Img,
			c.name,
			EXISTS(
					SELECT 1 FROM bookings AS bk
					JOIN detail_bookings AS db ON db.booking_id = bk.id
					WHERE db.book_id = b.id
					AND bk.start_date <= NOW()
					AND bk.end_date >= NOW()
					AND bk.actual_return_date IS NULL
				) AS is_borrowed
		FROM books AS b
		JOIN categories AS c ON c.id = b.category_id
		WHERE b.id = ?
		`
		var book Book
		err := db.QueryRow(queryDetail, id).Scan(&book.ID, &book.Title, &book.Isbn, &book.Img, &book.CategoryName, &book.IsBorrowed)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.String(http.StatusNotFound, "Book Not Found")
				return
			}
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		ctx.HTML(http.StatusOK, "view_detail_user.html", gin.H{
			"Book":       book,
			"Search":     search,
			"CategoryID": categoryID,
			"FromHome":   fromHome,
		})
	})

	app.GET("settings_user", AuthMiddleware, func(ctx *gin.Context) {
		claimInterface, exists := ctx.Get("Data")
		if !exists {
			ctx.String(http.StatusInternalServerError, "Failed to get user data")
			return
		}
		claim := claimInterface.(jwt.MapClaims)
		userID := int(claim["id"].(float64))

		var user User
		err := db.QueryRow("SELECT id, name FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Name)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		ctx.HTML(http.StatusOK, "settings_user.html", gin.H{
			"User": user,
		})
	})

	app.POST("/settings_user", AuthMiddleware, func(ctx *gin.Context) {
		password := ctx.PostForm("password")
		claimsInterface, exists := ctx.Get("Data")
		if !exists {
			ctx.String(http.StatusInternalServerError, "Failed to get user data")
			return
		}
		claim := claimsInterface.(jwt.MapClaims)
		userID := int(claim["id"].(float64))

		hashedPasword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		result, err := db.Exec("UPDATE users SET password = ? WHERE id = ?", string(hashedPasword), userID)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		row, err := result.RowsAffected()
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		if row == 0 {
			ctx.String(http.StatusInternalServerError, "Failed to Update Password")
			return
		}

		ctx.Redirect(http.StatusFound, "/home")

	})

	app.GET("/bookings_in_user", AuthMiddleware, func(ctx *gin.Context) {
		page, _ := strconv.Atoi(ctx.Query("page"))
		if page < 1 {
			page = 1
		}
		limit := 3
		offset := (page - 1) * limit

		claimsInterface, exists := ctx.Get("Data")
		if !exists {
			ctx.String(http.StatusInternalServerError, "Failed to get user data")
			return
		}
		claim := claimsInterface.(jwt.MapClaims)
		userID := int(claim["id"].(float64))

		status := ctx.DefaultQuery("status", "loan")

		queryCount := `
			SELECT
				COUNT(CASE 
					WHEN bk.actual_return_date IS NULL THEN db.book_id  
				END) AS borrowed_count,
				COUNT(CASE 
					WHEN bk.actual_return_date IS NOT NULL THEN db.book_id  
				END) AS returned_count
			FROM bookings bk
            JOIN detail_bookings db ON db.booking_id = bk.id
            WHERE bk.user_id = ?
		`

		var count BooksCount
		err := db.QueryRow(queryCount, userID).
			Scan(&count.BookBorrowed, &count.BookAvailable)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		queryPenalty := `
		SELECT COALESCE(SUM(penalty_fee), 0)
		FROM bookings
		WHERE actual_return_date IS NOT NULL
		AND user_id = ?
		`

		var countPenalty float64
		err = db.QueryRow(queryPenalty, userID).Scan(&countPenalty)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		baseQuery := `
			SELECT b.id, b.title, b.img
			FROM books b
			JOIN detail_bookings db ON db.book_id = b.id
			JOIN bookings bk ON db.booking_id = bk.id
			WHERE bk.user_id = ?
		`

		var statusCondition string
		var totalItems int

		if status == "returned" {
			statusCondition = " AND bk.actual_return_date IS NOT NULL "
			totalItems = count.BookAvailable
		} else {
			statusCondition = " AND bk.actual_return_date IS NULL "
			totalItems = count.BookBorrowed
		}

		queryBorrow := fmt.Sprintf("%s %s LIMIT ? OFFSET ?", baseQuery, statusCondition)

		rows, err := db.Query(queryBorrow, userID, limit, offset)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}
		defer rows.Close()

		var books []Book
		for rows.Next() {
			var b Book
			if err := rows.Scan(&b.ID, &b.Title, &b.Img); err != nil {
				ctx.String(http.StatusInternalServerError, err.Error())
				return
			}
			books = append(books, b)
		}

		totalPage := int(math.Ceil(float64(totalItems) / float64(limit)))
		if page > totalPage && totalPage != 0 {
			ctx.Redirect(http.StatusFound, fmt.Sprintf("bookings_in_user?page=%d&status=%s", totalPage, status))
			return
		}

		pages := make([]int, totalPage)
		for i := 0; i < totalPage; i++ {
			pages[i] = i + 1
		}

		ctx.HTML(http.StatusOK, "bookings_in_user.html", gin.H{
			"Count":   count,
			"Books":   books,
			"Pages":   pages,
			"Page":    page,
			"Penalty": countPenalty,
			"Status":  status,
		})
	})

	app.GET("/details_book_in_user/:book_id", AuthMiddleware, func(ctx *gin.Context) {
		bookID, _ := strconv.Atoi(ctx.Param("book_id"))
		page, _ := strconv.Atoi(ctx.Query("page"))
		status := ctx.Query("status")
		if page < 1 {
			page = 1
		}

		claimsInterface, exists := ctx.Get("Data")
		if !exists {
			ctx.String(http.StatusInternalServerError, "Failed to get user data")
			return
		}
		claims := claimsInterface.(jwt.MapClaims)
		userID := int(claims["id"].(float64))

		query := `
			SELECT 
				bk.id,
				b.title,
				b.isbn,
				b.img,
				c.name,
				bk.start_date,
				bk.end_date,
				bk.actual_return_date,
				bk.penalty_fee
			FROM bookings bk
			JOIN detail_bookings db ON db.booking_id = bk.id
			JOIN books b ON b.id = db.book_id
			JOIN categories c ON c.id = b.category_id
			WHERE b.id = ?
			AND bk.user_id = ?
			AND bk.actual_return_date IS NOT NULL
			ORDER BY bk.actual_return_date DESC
			LIMIT 1
		`

		var book BookDetail
		err := db.QueryRow(query, bookID, userID).Scan(
			&book.ID,
			&book.Title,
			&book.Isbn,
			&book.Img,
			&book.CategoryName,
			&book.StartDate,
			&book.EndDate,
			&book.ActualReturnDate,
			&book.Penalty,
		)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.String(http.StatusNotFound, "Booking not found")
				return
			}
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		location, _ := time.LoadLocation("Asia/Jakarta")
		book.StartStr = book.StartDate.In(location).Format("02 January 2006")
		book.EndStr = book.EndDate.In(location).Format("02 January 2006")

		if book.ActualReturnDate.Valid {
			book.ActualReturnStr = book.ActualReturnDate.Time.In(location).Format("02 January 2006")
		} else {
			book.ActualReturnStr = "-"
		}

		ctx.HTML(http.StatusOK, "details_book_in_user.html", gin.H{
			"Book":   book,
			"Page":   page,
			"Status": status,
		})
	})

	app.Run(":8080")

}
