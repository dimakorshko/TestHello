package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	_ "io"
	"io/ioutil"
	"math/big"
	_ "mime/multipart"
	"os/exec"
	"strings"
	"time"

	"github.com/fullsailor/pkcs7"

	"database/sql"
	_ "fmt"
	"html/template"
	"log"
	"net/http"
	_ "net/url"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

type ReplitRequest struct {
	Code     string `json:"code"`
	Language string `json:"language"`
}

type ReplitResponse struct {
	Result string `json:"result"`
}

var (
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	certificate *x509.Certificate
)

var db *sql.DB
var user *User
var result string = ""

func main() {
	var err error
	port := os.Getenv("PORT") //Установка порта
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

	fs := http.FileServer(http.Dir("static")) // Каталог со статическими файлами, для работы CSS и JS
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Регистрация и обработка маршрутов
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/main", mainHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/signContract", contractHandler)
	http.HandleFunc("/final", finalHandler)

	log.Println("Server started on http://localhost:443")

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}

// Отображение домашней страницы с регистрацией и авторизацией
func homeHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, []string{"index.html"}, nil)
}

func finalHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, []string{"final.html"}, result)
}

/**/
/*Подпись контракта*/
/**/
func contractHandler(w http.ResponseWriter, r *http.Request) {
	generateKeysAndCertificate()
	//printKeysAndCertificate()

	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	// Парсинг формы
	err := r.ParseMultipartForm(32 << 20) // Указывает максимальный размер файла
	if err != nil {
		http.Error(w, "Ошибка при обработке формы", http.StatusInternalServerError)
		return
	}

	// Получение файла из формы
	file, handler, err := r.FormFile("upload-file")
	if err != nil {
		http.Error(w, "Не удалось получить файл", http.StatusBadRequest)
		fmt.Println(http.StatusBadRequest)
		return
	}
	defer file.Close()
	fmt.Println(file)
	// Чтение данных файла
	contractData, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Не удалось прочитать данные файла", http.StatusInternalServerError)
		fmt.Println(http.StatusInternalServerError)
		return
	}

	// Пример: Вывод данных файла на серверной стороне
	fmt.Println("Данные файла:", string(contractData))

	// Отправка ответа клиентской части
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Файл успешно принят и обработан"))

	// Перевірка контракту перед підписанням
	err = validateContract(contractData)
	handleError("Неприпустимий контракт:", err)

	// Підписання контракту
	signedContract, err := signContract(contractData)
	handleError("Не вдалося підписати смарт контракт:", err)

	// Вивід на екран результату підписання контракту
	fmt.Println("Смарт контракт підписано успішно.")

	// Збереження підписаного контракту у файл
	err = saveSignedContract(signedContract)
	handleError("Не вдалося зберегти підписаний контракт:", err)

	// Виконання пайтоновської програми з підписаного контракту
	result, err := executePythonProgram(contractData)
	if err != nil {
		fmt.Println("Помилка при виконанні пайтоновської програми:", err)
		return
	}

	fmt.Println("Результат виконання пайтоновської програми:")
	fmt.Println(result)

	fmt.Println("Операції завершено успішно.")
	handler = handler
}

/*Регистрация*/
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

/*АВТОРИЗАЦИЯ*/
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

/*Главная страница, где можно подписать контракт или перейти на профиль*/
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

// Считывание с БД данных по имени
func getUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, email, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Считывание с БД логина и пароля
func getUserByUsernameAndPassword(username, password string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, email, password FROM users WHERE username = ? AND password = ?", username, password).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Функция которая запускает хтмловские файлы
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

// generateKeysAndCertificate генерує приватний ключ, публічний ключ і самопідписаний сертифікат
func generateKeysAndCertificate() {
	// Генерування приватного ключа
	privateKey, _ = generatePrivateKey()
	publicKey = &privateKey.PublicKey
	// Генерування самопідписаного сертифіката
	certificate, _ = generateCertificate(privateKey)
}

// generatePrivateKey генерує приватний ключ RSA
func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048) // Розмір ключа RSA встановлено на 2048 біт
}

// generateCertificate створює самопідписаний сертифікат
func generateCertificate(privateKey *rsa.PrivateKey) (*x509.Certificate, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// printKeysAndCertificate виводить на екран публічний ключ, приватний ключ і сертифікат
func printKeysAndCertificate() {
	fmt.Println("Публічний ключ:")
	fmt.Println(formatPublicKey(publicKey))

	fmt.Println("Приватний ключ:")
	fmt.Println(formatPrivateKey(privateKey))

	fmt.Println("Сертифікат:")
	fmt.Println(formatCertificate(certificate))
}

// formatPublicKey форматує публічний ключ для виведення на екран
func formatPublicKey(publicKey *rsa.PublicKey) string {
	pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return string(pemKey)
}

// formatPrivateKey форматує приватний ключ для виведення на екран
func formatPrivateKey(privateKey *rsa.PrivateKey) string {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return string(pemKey)
}

// formatCertificate форматує сертифікат для виведення на екран
func formatCertificate(cert *x509.Certificate) string {
	certBytes := cert.Raw
	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	return string(pemCert)
}

// handleError обробляє помилки та виводить повідомлення про помилку
func handleError(message string, err error) {
	if err != nil {
		fmt.Println(message, err)
	}
}

// readContractFile зчитує вміст файлу контракту
func readContractFile(filename string) ([]byte, error) {
	contractData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return contractData, nil
}

// validateContract перевіряє контракт перед підписанням
func validateContract(contract []byte) error {
	contractStr := string(contract)
	lines := strings.Split(contractStr, "\n")

	// Перевірка довжини тіла контракту
	if len(lines) > 30 {
		return errors.New("Тіло контракту перевищує 30 рядків")
	}

	// Перевірка наявності math або numpy
	hasMath := false
	hasNumpy := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.Contains(trimmedLine, "import math") {
			hasMath = true
		} else if strings.Contains(trimmedLine, "import numpy") {
			hasNumpy = true
		} else if strings.Contains(trimmedLine, "open(") || strings.Contains(trimmedLine, "socket.") {
			return errors.New("Контракт не може містити виклики функцій роботи з файлами або мережею")
		}
	}

	if !hasMath && !hasNumpy {
		return errors.New("Контракт повинен містити імпорт бібліотеки math або numpy")
	}

	return nil
}

// signContract підписує контракт за допомогою приватного ключа
func signContract(contract []byte) ([]byte, error) {
	p7, err := pkcs7.NewSignedData(contract)
	if err != nil {
		return nil, err
	}

	if err := p7.AddSigner(certificate, privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}

	signedData, err := p7.Finish()
	if err != nil {
		return nil, err
	}

	return signedData, nil
}

// saveSignedContract зберігає підписаний контракт у файл
func saveSignedContract(signedContract []byte) error {
	return ioutil.WriteFile("signed_contract.p7s", signedContract, 0644)
}

func executePythonProgram(contractData []byte) (string, error) {
	// Создаем команду для запуска питоновской программы
	cmd := exec.Command("python")

	// Устанавливаем входные данные для программы
	cmd.Stdin = bytes.NewReader(contractData)

	// Создаем буфер для хранения вывода программы
	var output bytes.Buffer
	cmd.Stdout = &output

	// Выполняем команду
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	result = output.String()
	// Возвращаем результат выполнения программы в виде строки
	return output.String(), nil
}
