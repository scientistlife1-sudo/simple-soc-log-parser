import os
import re

# 1. Задаем опасные сигнатуры (маркеры атак), по которым будем ловить хакеров
ATTACK_SIGNATURES = {
    "SQL-Injection": [r"'", r"UNION", r"SELECT", r"OR\s+1=1", r"OR\s+'1'='1"],
    "XSS (Скриптинг)": [r"<script>", r"alert\(", r"javascript:"],
    "Поиск бэкапов/секретов": [r"\.bak", r"\.env", r"\.git", r"config"]
}

def analyze_logs(logfile_path):
    if not os.path.exists(logfile_path):
        print(f"[-] Файл {logfile_path} не найден! Проверь путь.")
        return

    print(f"[+] Начинаем анализ файла: {logfile_path}\n" + "="*50)
    
    alerts_count = 0

    # 2. Читаем файл с логами построчно
    with open(logfile_path, "r", encoding="utf-8") as file:
        for line in file:
            # Вытаскиваем IP, сам запрос и код ответа регулярным выражением
            match = re.match(r"(\S+) .*? \[.*?\] \"\s*(.*?)\s*\" (\d+)", line)
            
            if match:
                ip = match.group(1)
                request = match.group(2)
                status_code = match.group(3)

                # 3. Проверяем запрос на наличие сигнатур атак
                for attack_type, regex_list in ATTACK_SIGNATURES.items():
                    for regex in regex_list:
                        if re.search(regex, request, re.IGNORECASE):
                            print(f"[🚨 ALERT] Обнаружена подозрительная активность!")
                            print(f"    • Атакующий IP: {ip}")
                            print(f"    • Тип угрозы:  {attack_type}")
                            print(f"    • Сам запрос:  {request}")
                            print(f"    • Код ответа:  {status_code}")
                            print("-" * 50)
                            alerts_count += 1
                            break 
                            
    print(f"[+] Анализ завершен. Всего найдено угроз: {alerts_count}")

if __name__ == "__main__":
    analyze_logs("access.log")