
#ОПАСНОСТЬ: Используем версию Ubuntu (14.04), в которой куча уязвимостей
FROM ubuntu:14.04

# Имитируем копирование парсера логов внутрь контейнера
COPY parser.py /app/parser.py

CMD ["python3", "/app/parser.py"]
