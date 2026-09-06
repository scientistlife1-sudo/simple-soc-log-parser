import os
import re

# Наш список опасных маркеров атак
ATTACK_SIGNATURES = {
    "SQL-Injection": [r"'", r"UNION", r"SELECT", r"OR\s+1=1", r"OR\s+'1'='1 uncoated"],
    "XSS (Скриптинг)": [r"<script>", r"alert\(", r"javascript:"],
    "Поиск бэкапов/секретов": [r"\.bak", r"\.env", r"\.git", r"config"]
}

def analyze_logs(logfile_path):
    if not os.path.exists(logfile_path):
        print(f"[-] Файл {logfile_path} не найден!")
        return

    print(f"[+] Начинаем анализ файла: {logfile_path}\n" + "="*50)
    
    alerts_count = 0
    # Словарь для подсчета атак с каждого IP
    ip_counter = {}

    with open(logfile_path, "r", encoding="utf-8") as file:
        for line in file:
            match = re.match(r"(\S+) .*? \[.*?\] \"\s*(.*?)\s*\" (\d+)", line)
            
            if match:
                ip = match.group(1)
                request = match.group(2)
                status_code = match.group(3)

                for attack_type, regex_list in ATTACK_SIGNATURES.items():
                    for regex in regex_list:
                        if re.search(regex, request, re.IGNORECASE):
                            print(f"[ALERT] Обнаружена подозрительная активность!")
                            print(f"    • Атакующий IP: {ip}")
                            print(f"    • Тип угрозы:  {attack_type}")
                            print(f"    • Сам запрос:  {request}")
                            print("-" * 50)
                            
                            alerts_count += 1
                            
                            # Считаем атаку для конкретного IP
                            if ip in ip_counter:
                                ip_counter[ip] += 1
                            else:
                                ip_counter[ip] = 1
                            break 
                            
    print(f"[+] Анализ завершен. Всего найдено угроз: {alerts_count}\n")
    
    # Выводим статистику по самым активным IP-адресам
    print("="*50)
    print("ТОП ХАКЕРОВ (Количество зафиксированных атак):")
    print("="*50)
    
    if ip_counter:
        # Сортируем IP по значению (количеству атак) от большего к меньшему
        sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips:
            print(f"IP-адрес: {ip} ---> Атак: {count}")
    else:
        print("Подозрительных IP-адресов не обнаружено.")
    print("="*50)

if __name__ == "__main__":
    analyze_logs("access.log")
    
