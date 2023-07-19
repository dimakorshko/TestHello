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

var contractErors bool = true
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
		password TEXT NOT NULL,
		private_key TEXT, -- Поле для хранения приватного ключа в формате PEM
		public_key TEXT -- Поле для хранения публичного ключа в формате PEM
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
	//http.HandleFunc("/downloadPrivateKey", downloadPrivateKeyHandler)
	http.HandleFunc("/downloadPublicKey", downloadPublicKeyHandler)
	http.HandleFunc("/downloadSignedContract", downloadSignedContractHandler)

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

// getKeysFromDB retrieves the private and public keys from the database for the given username.
func getKeysFromDB(username string) (privateKey, publicKey string, err error) {
	err = db.QueryRow("SELECT private_key, public_key FROM users WHERE username = ?", username).Scan(&privateKey, &publicKey)
	if err != nil {
		return "", "", err
	}
	return privateKey, publicKey, nil
}

/*
	func downloadPrivateKeyHandler(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// Получаем приватный ключ из базы данных для текущего пользователя
			password := r.FormValue("password")

			// Получаем пароль из базы данных для текущего пользователя
			correctPassword, err := getPasswordFromDB(user.Username)
			fmt.Println(correctPassword)
			fmt.Println("A")
			fmt.Println(password)
			if err != nil {
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}

			// Сверяем введенный пароль с паролем из базы данных
			if password != correctPassword {
				http.Error(w, "Неправильний пароль", http.StatusUnauthorized)
				return
			}

			privateKey, err := getPrivateKeyFromDB(user.Username)
			if err != nil {
				//http.Error(w, "Server Error", http.StatusInternalServerError)
				http.ServeContent(w, r, "", time.Now(), bytes.NewReader([]byte("Private key not found")))
				return
			}

			// Отправляем приватный ключ в виде файла для скачивания
			w.Header().Set("Content-Disposition", "attachment; filename=private_key.pem")
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeContent(w, r, "", time.Now(), bytes.NewReader([]byte(privateKey)))
		}
	}
*/
func downloadPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем публичный ключ из базы данных для текущего пользователя
	publicKey, err := getPublicKeyFromDB(user.Username)
	if err != nil {
		http.ServeContent(w, r, "", time.Now(), bytes.NewReader([]byte("Public key not found")))
		//http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// Отправляем публичный ключ в виде файла для скачивания
	w.Header().Set("Content-Disposition", "attachment; filename=public_key.pem")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", time.Now(), bytes.NewReader([]byte(publicKey)))
}

func downloadSignedContractHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=signed_contract.p7s")
	w.Header().Set("Content-Type", "application/octet-stream")
	signedContract, err := ioutil.ReadFile("signed_contract.p7s")
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, "", time.Now(), bytes.NewReader(signedContract))
}

// ОТкрытие финальной страницы
func finalHandler(w http.ResponseWriter, r *http.Request) {
	if contractErors != true {
		renderTemplate(w, []string{"final.html"}, result)
	} else {
		renderTemplate(w, []string{"main.html"}, user)
	}
}

/**/
/*Подпись контракта*/
/**/
func contractHandler(w http.ResponseWriter, r *http.Request) {
	contractErors = true
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
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

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
	contractErors = false
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
	// generateKeysAndCertificate generates private and public keys, and a self-signed certificate.
	privateKeyPEM, publicKeyPEM, err := getKeysFromDB(user.Username)
	if err != nil || privateKeyPEM == "" || publicKeyPEM == "" {
		// If keys are missing in the database, generate new ones
		privateKey, _ = generatePrivateKey()
		publicKey := &privateKey.PublicKey

		// Format private and public keys to PEM format
		privateKeyPEM = formatPrivateKey(privateKey)
		publicKeyPEM = formatPublicKey(publicKey)

		// Save private and public keys to the database for the current user
		_, err = db.Exec("UPDATE users SET private_key = ?, public_key = ? WHERE username = ?", privateKeyPEM, publicKeyPEM, user.Username)
		if err != nil {
			fmt.Println("Failed to save keys to the database:", err)
			return
		}
	}

	// Parse private key from PEM format
	privateKey, err = parsePrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		fmt.Println("Failed to parse private key:", err)
		return
	}

	// Parse public key from PEM format
	publicKey, err = parsePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		fmt.Println("Failed to parse public key:", err)
		return
	}

	// Generate self-signed certificate
	certificate, _ = generateCertificate(privateKey)
	// Print information about keys and certificate
	fmt.Println("Private Key:")
	fmt.Println(formatPrivateKey(privateKey))

	fmt.Println("Public Key:")
	fmt.Println(formatPublicKey(publicKey))

	fmt.Println("Certificate:")
	fmt.Println(formatCertificate(certificate))
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

// Функция для получения приватного ключа из базы данных для текущего пользователя
func getPrivateKeyFromDB(username string) (string, error) {
	var privateKey string
	err := db.QueryRow("SELECT private_key FROM users WHERE username = ?", username).Scan(&privateKey)
	if err != nil {
		return "", err
	}
	return privateKey, nil
}

// Функция для получения публичного ключа из базы данных для текущего пользователя
func getPublicKeyFromDB(username string) (string, error) {
	var publicKey string
	err := db.QueryRow("SELECT public_key FROM users WHERE username = ?", username).Scan(&publicKey)
	if err != nil {
		return "", err
	}
	return publicKey, nil
}

// parsePrivateKeyFromPEM parses the private key from PEM format and returns an *rsa.PrivateKey.
func parsePrivateKeyFromPEM(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// parsePublicKeyFromPEM parses the public key from PEM format and returns an *rsa.PublicKey.
func parsePublicKeyFromPEM(pemKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func getPasswordFromDB(username string) (string, error) {
	var password string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&password)
	if err != nil {
		return "", err
	}
	return password, nil
}
