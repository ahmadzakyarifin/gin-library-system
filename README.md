# 📚 Gin Library Management System

Aplikasi Manajemen Perpustakaan sederhana yang dibangun menggunakan bahasa **Go (Golang)** dengan framework **Gin Web Framework**. Aplikasi ini mencakup fitur untuk Admin (pengelolaan buku, user, peminjaman) dan User (peminjaman pribadi, katalog buku).

Project ini berfokus pada backend logic, autentikasi, dan alur sistem,
dengan UI sederhana untuk mendukung fungsionalitas.

Project ini menggunakan **Server Side Rendering (SSR)** dengan template HTML.

## ⚠️ Disclaimer & Acknowledgements

Project ini dibuat sebagai media pembelajaran pribadi untuk mendalami bahasa **Go** dan framework **Gin**.

Project ini **bukanlah kode yang sempurna**. Sebelumnya, saya mempelajari logika dan alur sistem ini melalui kelas project berbasis **Express.js** yang diadakan oleh **Mas Aka (Getherloop)**. Saya kemudian menantang diri sendiri untuk menulis ulang (porting) sistem tersebut dari Node.js/Express ke **Golang/Gin**.

**Ucapan terima kasih yang sebesar-besarnya kepada:**
* **Mas Aka** (Getherloop) atas ilmunya.
* Para mentor lainnya yang telah membimbing selama proses belajar.

Silakan gunakan kode ini untuk referensi belajar, namun perlu diingat masih banyak ruang untuk refactoring dan perbaikan.

## 🚀 Fitur

### 🛡️ Admin Panel
* **Dashboard:** Statistik peminjaman bulanan (Chart), persentase ketepatan pengembalian, dan total denda.
* **Manajemen Kategori:** CRUD (Create, Read, Update, Delete) kategori buku.
* **Manajemen Buku:** CRUD buku, upload gambar/cover, status ketersediaan.
* **Manajemen User:** Membuat user, edit data, dan aktivasi/deaktivasi akun.
* **Transaksi Peminjaman:**
    * Mencatat peminjaman (Max 2 buku per user).
    * Validasi stok buku.
* **Pengembalian & Denda:**
    * Menghitung denda otomatis berdasarkan keterlambatan hari.
    * Pengaturan nominal denda per hari.
* **Riwayat:** Melihat detail riwayat peminjaman per user atau per buku.

### 👤 User Panel
* **Katalog Buku:** Mencari buku berdasarkan judul atau kategori.
* **Detail Buku:** Melihat status ketersediaan buku.
* **Riwayat Peminjaman:**
    * Melihat buku yang sedang dipinjam (Active Loan).
    * Melihat riwayat buku yang sudah dikembalikan.
* **Settings:** Mengubah password akun.

## 🛠️ Tech Stack

* **Language:** Go (Golang)
* **Framework:** [Gin Gonic](https://github.com/gin-gonic/gin)
* **Database:** MySQL
* **Driver:** `go-sql-driver/mysql`
* **Authentication:** JWT (JSON Web Token) & Cookies
* **Security:** Bcrypt (Password Hashing)
* **Charting:** `go-chart` (v2)
* **Environment:** `godotenv`
* **Frontend:** HTML Native, CSS (Tailwind di-include via CDN/Static), Go Templates.

## 📸 Tampilan Aplikasi (UI Preview)

### 🔐 Autentikasi & Keamanan
| Halaman Login | Akses Ditolak (Forbidden) |
| :---: | :---: |
| ![Login Page](screenshots/admin/login.png) | ![Forbidden Page](screenshots/admin/forbidden.png) |
| *Portal Masuk (Admin & User)* | *Tampilan jika User biasa mencoba akses Admin* |

### 🛡️ Panel Admin

#### 1. Dashboard & Pengaturan
| Dashboard | Settings (Denda) |
| :---: | :---: |
| ![Dashboard](screenshots/admin/admin_dashboard.png) | ![Settings](screenshots/admin/admin_settings.png) |
| *Statistik Peminjaman* | *Pengaturan Denda* |

#### 2. Manajemen Kategori
| Daftar Kategori | Tambah Kategori | Edit Kategori |
| :---: | :---: | :---: |
| ![List Kategori](screenshots/admin/admin_cat_list.png) | ![Create Kategori](screenshots/admin/admin_cat_create.png) | ![Update Kategori](screenshots/admin/admin_cat_update.png) |

#### 3. Manajemen User (Pengguna)
| Daftar User | Tambah User | Edit User |
| :---: | :---: | :---: |
| ![List User](screenshots/admin/admin_user_list.png) | ![Create User](screenshots/admin/admin_user_create.png) | ![Update User](screenshots/admin/admin_user_update.png) |

#### 4. Manajemen Buku
| Daftar Buku | Tambah Buku | Edit Buku |
| :---: | :---: | :---: |
| ![List Buku](screenshots/admin/admin_book_list.png) | ![Create Buku](screenshots/admin/admin_book_create.png) | ![Update Buku](screenshots/admin/admin_book_update.png) |

#### 5. Transaksi Peminjaman (Bookings)
| Daftar Peminjaman | Pengembalian Buku |
| :---: | :---: |
| ![List Booking](screenshots/admin/admin_booking_list.png) | ![Return Booking](screenshots/admin/admin_booking_return.png) |
| *List semua peminjaman aktif* | *Form pengembalian & denda* |

#### 6. Detail & Riwayat
| Filter by User | Detail History User |
| :---: | :---: |
| ![Booking by User](screenshots/admin/admin_booking_by_user.png) | ![Detail User](screenshots/admin/admin_booking_detail_user.png) |
| *Cari peminjaman per user* | *Detail riwayat user tertentu* |

| Filter by Book | Detail History Book |
| :---: | :---: |
| ![Booking by Book](screenshots/admin/admin_booking_by_book.png) | ![Detail Book](screenshots/admin/admin_booking_detail_book.png) |
| *Cari peminjaman per buku* | *Siapa saja yang pernah pinjam buku ini* |

---

### 👤 Panel User (Peminjam)

#### 1. Katalog & Pencarian
| Halaman Utama (Home) | Semua Buku (All) |
| :---: | :---: |
| ![Home User](screenshots/user/user_home.png) | ![All Books](screenshots/user/user_all_books.png) |
| *Kategori & Buku Populer* | *Lihat semua koleksi* |

#### 2. Detail & Aktivitas Saya
| Detail Buku | Peminjaman Saya |
| :---: | :---: |
| ![Detail Buku](screenshots/user/user_book_detail.png) | ![My Bookings](screenshots/user/user_my_bookings.png) |
| *Status & Info Buku* | *Buku yang sedang dipinjam & Riwayat* |

---

## 🗄️ Desain Database (ERD)

Berikut adalah struktur database yang digunakan:

![Database Schema](screenshots/database/erd.png)

## 📦 Instalasi & Cara Menjalankan

1.  **Clone Repository**
    ```bash
    git clone [https://github.com/username-anda/gin-library-system.git](https://github.com/username-anda/gin-library-system.git)
    cd gin-library-system
    ```

1.  **Setup Database**
    * Buat database baru di MySQL (misal: `library_db`).
    * Import file SQL (jika ada) untuk membuat struktur tabel.

2.  **Konfigurasi Environment (.env)**
    Buat file `.env` di root folder dan sesuaikan isinya:
    ```env
    DB_HOST=localhost
    DB_PORT=3306
    DB_USER=root
    DB_PASS=password_mysql_anda
    DB_NAME=library_db
    
    JWT_SECRET=rahasia_negara_api
    
    # Akun Admin Default (untuk login pertama kali)
    ADMIN_EMAIL=admin@gmail.com
    ADMIN_PASSWORD=admin123
    ```

3.  **Install Dependencies & Run**
    ```bash
    go mod tidy
    go run main.go
    ```


## Rencana Pengembangan (V2)

Pengembangan selanjutnya direncanakan meliputi:

- Migrasi ke REST API berbasis JSON
- Implementasi Client Side Rendering (CSR) secara parsial
- Manipulasi DOM untuk meningkatkan interaktivitas UI
- Refactoring kode menggunakan prinsip Clean Architecture
- Penambahan fitur baru dan penyempurnaan logika bisnis
- Eksplorasi teknologi tambahan untuk meningkatkan skalabilitas sistem
- Meningkatkan alur kerja pengembangan frontend dengan memanfaatkan tooling modern
