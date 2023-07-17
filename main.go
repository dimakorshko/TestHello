package main

import (
	"database/sql"
	_ "fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

var db *sql.DB
var user *User

func main() {
	var err error
	port := os.Getenv("PORT")
	if port == "" {
		port = "443" // Порт по умолчанию, если переменная окружения не установлена
	}

	// Открываем соединение с базой данных SQLite3

	db, err = sql.Open("sqlite3", "users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Создаем таблицу пользователей, если она не существует
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		email TEXT NOT NULL,
		password TEXT NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}

	fs := http.FileServer(http.Dir("static")) // Замените "static" на путь к каталогу со статическими файлами
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Регистрация и обработка маршрутов
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/main", mainHandler)
	http.HandleFunc("/profile", profileHandler)

	// Запуск сервера на порту 8080
	log.Println("Server started on http://localhost:443")
	//log.Fatal(http.ListenAndServe(":8080", nil))

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Отображение домашней страницы
	renderTemplate(w, []string{"index.html"}, nil)

}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Обработка регистрации нового пользователя
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirmPassword")

		// Проверка, что пользователь с таким именем пользователя не существует
		existingUser, err := getUserByUsername(username)
		if err != nil && err != sql.ErrNoRows {
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		if existingUser != nil {
			http.Error(w, "Username already exists", http.StatusBadRequest)
			return
		}

		// Проверка соответствия паролей
		if password != confirmPassword {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		// Вставка нового пользователя в базу данных
		_, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, password)
		if err != nil {
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		// Перенаправление на страницу авторизации
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Отображение страницы регистрации
	renderTemplate(w, []string{"templates/register.html"}, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Обработка попытки авторизации
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Проверка правильности логина и пароля
		user, err := getUserByUsernameAndPassword(username, password)
		if err != nil && err != sql.ErrNoRows {
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		if user == nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Создание сессии пользователя (можно использовать куки)
		// В данном примере просто сохраняем имя пользователя в URL запроса
		http.Redirect(w, r, "/main?username="+user.Username, http.StatusFound)
		return
	}

	// Отображение страницы авторизации
	renderTemplate(w, []string{"index.html"}, nil)

}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Получение пользователя по имени пользователя из базы данных
	var err error
	user, err = getUserByUsername(username)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.NotFound(w, r)
		return
	}

	// Отображение страницы для работы с контрактом
	renderTemplate(w, []string{"main.html"}, user)

}

func profileHandler(w http.ResponseWriter, r *http.Request) {

	// Отображение страницы для работы с контрактом
	renderTemplate(w, []string{"profile.html"}, user)

}

func getUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, email, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func getUserByUsernameAndPassword(username, password string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, email, password FROM users WHERE username = ? AND password = ?", username, password).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func renderTemplate(w http.ResponseWriter, tmplFiles []string, data interface{}) {
	tmpl, err := template.ParseFiles(tmplFiles...)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
}
