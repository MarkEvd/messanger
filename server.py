import socket
import threading
import time

HOST = '0.0.0.0'
PORT = 8080

clients = []
# Розширений словник для зберігання інформації про користувачів
user_info = {}  # {socket: {'username': str, 'status': str, 'last_seen': float}}


def broadcast(data, exclude_socket=None):
    """Розсилає дані всім підключеним клієнтам, крім вказаного."""
    for client in clients:
        if client != exclude_socket:
            try:
                client.sendall(data)
            except:
                pass


def send_user_list(target_socket=None):
    """Відправляє список користувачів та їх статуси вказаному клієнту або всім.

    Формат: USERLIST@System@username1:status1,username2:status2,...
    """
    if not user_info:
        return

    # Створюємо список користувачів у форматі "ім'я:статус"
    user_list = []
    for sock, info in user_info.items():
        if sock in clients:  # Перевіряємо, чи клієнт ще підключений
            user_list.append(f"{info['username']}:{info['status']}")

    # Формуємо повідомлення зі списком
    userlist_data = f"USERLIST@System@{','.join(user_list)}\n".encode('utf-8')

    if target_socket:
        # Надсилаємо одному клієнту
        try:
            target_socket.sendall(userlist_data)
        except:
            pass
    else:
        # Надсилаємо всім клієнтам
        for client in clients:
            try:
                client.sendall(userlist_data)
            except:
                pass


def notify_status_change(username, status):
    """Сповіщає всіх клієнтів про зміну статусу користувача.

    Формат: USERSTATUS@username@status
    """
    status_data = f"USERSTATUS@{username}@{status}\n".encode('utf-8')
    broadcast(status_data)


def handle_client_message(client_socket, data):
    """Обробляє повідомлення від клієнта залежно від його типу."""
    try:
        # Декодуємо дані та розділяємо на частини
        message = data.decode('utf-8', errors='ignore')
        parts = message.split('@', 3)

        if len(parts) < 2:
            # Якщо формат повідомлення невірний, просто пересилаємо його
            broadcast(data, exclude_socket=client_socket)
            return

        msg_type = parts[0]
        username = parts[1]

        # Перевіряємо, чи існує запис для цього сокета
        if client_socket not in user_info:
            user_info[client_socket] = {
                'username': username,
                'status': 'online',
                'last_seen': time.time()
            }
        else:
            # Оновлюємо час останньої активності
            user_info[client_socket]['last_seen'] = time.time()

        # Обробка різних типів повідомлень
        if msg_type == "TEXT" or msg_type == "IMAGE":
            # Оновлюємо статус на "online" (активний)
            if user_info[client_socket]['status'] != 'online':
                user_info[client_socket]['status'] = 'online'
                notify_status_change(username, 'online')

            # Пересилаємо повідомлення іншим клієнтам
            broadcast(data, exclude_socket=client_socket)

        elif msg_type == "STATUS":
            # Обробка повідомлення про зміну статусу
            if len(parts) >= 3:
                new_status = parts[2]
                user_info[client_socket]['status'] = new_status
                notify_status_change(username, new_status)

        elif msg_type == "USERNAME":
            # Обробка зміни імені користувача
            if len(parts) >= 3:
                old_username = username
                new_username = parts[2]

                # Оновлюємо ім'я в словнику
                user_info[client_socket]['username'] = new_username

                # Сповіщаємо всіх про зміну імені
                name_change_msg = f"TEXT@System@{old_username} змінив(ла) ім'я на {new_username}.\n".encode('utf-8')
                broadcast(name_change_msg)

                # Оновлюємо список користувачів для всіх
                send_user_list()

        elif msg_type == "REQUEST":
            # Обробка запитів від клієнта
            if len(parts) >= 3:
                request_type = parts[2]

                if request_type == "userlist":
                    # Надсилаємо список користувачів
                    send_user_list(client_socket)
        else:
            # Для інших типів повідомлень просто пересилаємо
            broadcast(data, exclude_socket=client_socket)

    except Exception as e:
        print(f"Помилка обробки повідомлення: {e}")


def handle_client(client_socket):
    """Обробляє з'єднання з клієнтом."""
    try:
        # Отримуємо перше повідомлення (зазвичай повідомлення про підключення)
        data = client_socket.recv(4096)
        if not data:
            return

        # Обробляємо початкове повідомлення, щоб отримати ім'я користувача
        handle_client_message(client_socket, data)

        # Отримуємо ім'я користувача
        if client_socket in user_info:
            username = user_info[client_socket]['username']

            # Повідомляємо всіх про нового користувача
            join_msg = f"USERJOIN@{username}\n".encode('utf-8')
            broadcast(join_msg, exclude_socket=client_socket)

            # Надсилаємо список користувачів новому клієнту
            send_user_list(client_socket)

        # Основний цикл прийому повідомлень
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            # Обробляємо повідомлення
            handle_client_message(client_socket, data)

    except Exception as e:
        print(f"Помилка обробки клієнта: {e}")

    finally:
        # Відключення клієнта
        try:
            if client_socket in user_info:
                username = user_info[client_socket]['username']

                # Повідомляємо всіх про відключення користувача
                disconnect_msg = f"USERLEAVE@{username}\n".encode('utf-8')
                broadcast(disconnect_msg)

                # Видаляємо інформацію про користувача
                del user_info[client_socket]
        except Exception as e:
            print(f"Помилка при відключенні клієнта: {e}")

        if client_socket in clients:
            clients.remove(client_socket)

        try:
            client_socket.close()
        except:
            pass


def status_monitor():
    """Фоновий потік для моніторингу статусів користувачів."""
    while True:
        current_time = time.time()

        # Перевіряємо всіх користувачів
        for sock in list(user_info.keys()):
            try:
                # Якщо користувач не був активний більше 5 хвилин
                if current_time - user_info[sock]['last_seen'] > 300:  # 5 хвилин
                    if user_info[sock]['status'] != 'away' and sock in clients:
                        # Змінюємо статус на "away"
                        user_info[sock]['status'] = 'away'

                        # Сповіщаємо всіх про зміну статусу
                        notify_status_change(user_info[sock]['username'], 'away')
            except:
                pass  # Ігноруємо помилки

        # Спимо 60 секунд перед наступною перевіркою
        time.sleep(60)


def main():
    """Основна функція сервера."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Сервер запущено на {HOST}:{PORT}")

    # Запускаємо фоновий потік для моніторингу статусів
    status_thread = threading.Thread(target=status_monitor)
    status_thread.daemon = True
    status_thread.start()

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Підключився клієнт: {addr}")
            clients.append(client_socket)

            t = threading.Thread(target=handle_client, args=(client_socket,))
            t.daemon = True  # Потік стає фоновим
            t.start()
    except KeyboardInterrupt:
        print("Сервер завершує роботу...")
    finally:
        # Закриваємо всі з'єднання при завершенні
        for client in clients:
            try:
                client.close()
            except:
                pass
        server_socket.close()
        print("Сервер зупинено.")


if __name__ == "__main__":
    main()
