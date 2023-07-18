# Указываем базовый образ
FROM golang:latest
FROM python:latest

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем файлы проекта в рабочую директорию
COPY . .

# Устанавливаем зависимости Python из requirements.txt
RUN pip install -r requirements.txt
# Собираем программу
RUN go build -o main

# Указываем команду, которая будет выполняться при запуске контейнера
CMD ["./main"]
