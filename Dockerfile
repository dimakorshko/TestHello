# Указываем базовый образ
FROM golang:latest
FROM python:latest

RUN apt-get update && apt-get install -y golang

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
