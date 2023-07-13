package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Порт по умолчанию, если переменная окружения не установлена
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, World!")
	})

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}

	// Подключение к базе данных SQLite
	db, err := sql.Open("sqlite3", "test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Создание таблицы пользователей, если она не существует
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		email TEXT NOT NULL,
		password TEXT NOT NULL,
		phone TEXT NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		// Получение значения куки с именем пользователя
		cookie, err := r.Cookie("username")
		if err != nil || cookie.Value == "" {
			// Если куки не установлено или пустое значение, перенаправляем на форму авторизации
			http.Redirect(w, r, "/form.html", http.StatusFound)
			return
		}

		// Имя пользователя
		username := cookie.Value
		fmt.Println(username)
		// Отображение страницы аккаунта
		http.ServeFile(w, r, "account.html")
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Чтение данных из формы
			err := r.ParseForm()
			if err != nil {
				log.Println(err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			login := r.Form.Get("login")
			password := r.Form.Get("password")

			// Проверка правильности логина и пароля в базе данных
			var dbUsername string
			var dbPassword string
			var dbEmail string
			var dbPhone string
			err = db.QueryRow("SELECT username, password, email, phone FROM users WHERE username = ?", login).Scan(&dbUsername, &dbPassword, &dbEmail, &dbPhone)
			if err != nil {
				if err == sql.ErrNoRows {
					// Неправильный логин
					http.Redirect(w, r, "/form.html", http.StatusFound)
					return
				}
				log.Println(err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			if password == dbPassword {
				// Успешная авторизация
				cookie := &http.Cookie{
					Name:  "username",
					Value: login,
					Path:  "/",
				}
				http.SetCookie(w, cookie)

				emailCookie := &http.Cookie{
					Name:  "email",
					Value: dbEmail,
					Path:  "/",
				}
				http.SetCookie(w, emailCookie)

				phoneCookie := &http.Cookie{
					Name:  "phone",
					Value: dbPhone,
					Path:  "/",
				}
				http.SetCookie(w, phoneCookie)

				http.Redirect(w, r, "/account", http.StatusFound)
				return
			}

			// Неправильный пароль
			http.Redirect(w, r, "/form.html", http.StatusFound)
			return
		}

		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	// Обработчик POST запроса на эндпоинт /user
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Отображение формы для ввода данных пользователя
			http.ServeFile(w, r, "form.html")
			return
		} else if r.Method == http.MethodPost {
			// Чтение данных из формы
			err := r.ParseForm()
			if err != nil {
				log.Println(err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			username := r.Form.Get("username")
			email := r.Form.Get("email")
			password := r.Form.Get("password")
			phone := r.Form.Get("phone")

			// Вставка данных в базу данных
			result, err := db.Exec("INSERT INTO users (username, email, password, phone) VALUES (?, ?, ?, ?)", username, email, password, phone)
			if err != nil {
				log.Println(err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			// Получение идентификатора нового пользователя
			userID, _ := result.LastInsertId()

			// Отображение сообщения об успешном добавлении пользователя
			message := fmt.Sprintf("Пользователь успешно добавлен. ID: %d", userID)
			fmt.Fprintln(w, message)
			return
		}

		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	// Запуск сервера на порту 8080
	//log.Fatal(http.ListenAndServe(":8080", nil))
}
