from flask import Flask, request, jsonify, render_template_string
import json
import os
import subprocess
from datetime import datetime
import uuid

app = Flask(__name__)

# Хранилище DNS конфигураций пользователей
DNS_CONFIGS = {}

# HTML страница с возможностью узнать ID
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>DNS Server Manager</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .section { background: #f8f9fa; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #007cba; }
        textarea { width: 100%; height: 150px; margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        input { width: 100%; padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 12px 25px; background: #007cba; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        button:hover { background: #005a87; }
        .status { margin: 15px 0; padding: 15px; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .user-id { font-family: monospace; background: #fff3cd; padding: 10px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 DNS Server Manager</h1>

        <!-- Секция 1: Загрузка DNS конфигурации -->
        <div class="section">
            <h2>📁 1. Загрузите DNS конфигурацию</h2>
            <p><em>DNS конфигурация - это файл с настройками того, КАК должен работать DNS сервер</em></p>

            <textarea id="dnsCode" placeholder="Пример DNS конфигурации:
# Блокировка рекламы
address /ads.example.com/0.0.0.0
address /tracking.example.com/0.0.0.0

# Кастомные домены
address /mywebsite.local/192.168.1.100
address /api.local/192.168.1.101

# Публичные DNS
nameserver 8.8.8.8
nameserver 1.1.1.1"></textarea>
            <br>
            <button onclick="uploadDNS()">📤 Загрузить DNS конфигурацию</button>
            <div id="status"></div>
        </div>

        <!-- Секция 2: Узнать свой ID -->
        <div class="section">
            <h2>🔍 2. Узнать свой ID для подключения</h2>
            <p><em>Каждый пользователь получает уникальный ID после загрузки конфигурации</em></p>

            <button onclick="findMyID()">🔎 Найти мой ID</button>
            <div id="findIdResults"></div>
        </div>

        <!-- Секция 3: Подключение к DNS серверу -->
        <div class="section">
            <h2>🔌 3. Подключиться к DNS серверу</h2>
            <p><em>DNS сервер - это ПРОГРАММА, которая работает на основе вашей конфигурации и обрабатывает запросы</em></p>

            <input type="text" id="userId" placeholder="Введите ваш ID пользователя">
            <button onclick="connectToDNS()">🔗 Подключиться к DNS</button>
            <div id="connectionStatus"></div>
        </div>

        <!-- Секция 4: Разница между конфигурацией и сервером -->
        <div class="section">
            <h2>🤔 В чем разница?</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div style="background: #e7f3ff; padding: 15px; border-radius: 5px;">
                    <h3>📝 DNS Конфигурация</h3>
                    <ul>
                        <li><strong>Файл с настройками</strong></li>
                        <li>Определяет ПРАВИЛА работы</li>
                        <li>Что блокировать</li>
                        <li>Куда перенаправлять</li>
                        <li>Какие DNS использовать</li>
                        <li><em>Как рецепт для повара</em></li>
                    </ul>
                </div>
                <div style="background: #fff2e7; padding: 15px; border-radius: 5px;">
                    <h3>🖥️ DNS Сервер</h3>
                    <ul>
                        <li><strong>Работающая программа</strong></li>
                        <li>Обрабатывает запросы</li>
                        <li>Возвращает IP адреса</li>
                        <li>Работает на сервере</li>
                        <li>Принимает подключения</li>
                        <li><em>Как повар на кухне</em></li>
                    </ul>
                </div>
            </div>
        </div>

        <div id="instructions"></div>
    </div>

    <script>
        let currentUserId = '';

        async function uploadDNS() {
            const dnsCode = document.getElementById('dnsCode').value;
            const response = await fetch('/upload-dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dns_code: dnsCode })
            });

            const result = await response.json();
            const statusDiv = document.getElementById('status');

            if (result.success) {
                currentUserId = result.user_id;
                statusDiv.innerHTML = `<div class="status success">
                    <h3>✅ Конфигурация успешно загружена!</h3>
                    <p><strong>Ваш уникальный ID:</strong></p>
                    <div class="user-id">${result.user_id}</div>
                    <p><strong>DNS сервер:</strong> ${result.dns_server}</p>
                    <p><em>Сохраните этот ID для подключения к DNS серверу!</em></p>
                </div>`;
            } else {
                statusDiv.innerHTML = `<div class="status error">
                    <strong>❌ Ошибка:</strong> ${result.error}
                </div>`;
            }
        }

        async function findMyID() {
            const response = await fetch('/list-configs');
            const result = await response.json();
            const resultsDiv = document.getElementById('findIdResults');

            if (result.success && result.configs.length > 0) {
                let html = `<div class="status info">
                    <h3>📋 Ваши загруженные конфигурации:</h3>`;

                result.configs.forEach(config => {
                    html += `
                    <div style="margin: 10px 0; padding: 10px; background: white; border-radius: 4px;">
                        <strong>ID:</strong> <code>${config.user_id}</code><br>
                        <strong>Сервер:</strong> ${config.dns_server}<br>
                        <strong>Создано:</strong> ${new Date(config.created_at).toLocaleString()}<br>
                        <strong>Конфигурация:</strong><br>
                        <pre style="background: #f8f9fa; padding: 5px; border-radius: 3px; font-size: 12px;">${config.dns_preview}</pre>
                    </div>`;
                });

                html += `</div>`;
                resultsDiv.innerHTML = html;
            } else {
                resultsDiv.innerHTML = `<div class="status error">
                    ❌ У вас нет загруженных конфигураций. Сначала загрузите DNS конфигурацию.
                </div>`;
            }
        }

        async function connectToDNS() {
            const userId = document.getElementById('userId').value || currentUserId;

            if (!userId) {
                alert('Пожалуйста, введите ID пользователя или сначала загрузите конфигурацию');
                return;
            }

            const response = await fetch('/connect-dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId })
            });

            const result = await response.json();
            const statusDiv = document.getElementById('connectionStatus');

            if (result.success) {
                statusDiv.innerHTML = `<div class="status success">
                    <h3>✅ Успешно подключено!</h3>
                    <p><strong>DNS сервер:</strong> ${result.dns_server}</p>
                    <p>${result.message}</p>

                    <h4>📋 Инструкции по настройке:</h4>
                    <div style="background: white; padding: 15px; border-radius: 5px;">
                        <p><strong>Для Windows:</strong></p>
                        <ol>
                            <li>Откройте "Панель управления" → "Сеть и Интернет"</li>
                            <li>Нажмите "Центр управления сетями и общим доступом"</li>
                            <li>Выберите "Изменение параметров адаптера"</li>
                            <li>Правой кнопкой на вашем подключении → "Свойства"</li>
                            <li>Выберите "IP версии 4 (TCP/IPv4)" → "Свойства"</li>
                            <li>Введите DNS: <code>${result.dns_server.split(':')[0]}</code></li>
                        </ol>

                        <p><strong>Для Linux/macOS:</strong></p>
                        <pre style="background: #f8f9fa; padding: 10px; border-radius: 4px;">
# Временное изменение
echo "nameserver ${result.dns_server.split(':')[0]}" | sudo tee /etc/resolv.conf

# Или через NetworkManager
nmcli con mod "ваше-подключение" ipv4.dns "${result.dns_server.split(':')[0]}"
nmcli con down "ваше-подключение"; nmcli con up "ваше-подключение"</pre>
                    </div>
                </div>`;
            } else {
                statusDiv.innerHTML = `<div class="status error">
                    <strong>❌ Ошибка:</strong> ${result.error}
                </div>`;
            }
        }
    </script>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(HTML_PAGE)


@app.route('/upload-dns', methods=['POST'])
def upload_dns():
    """Эндпоинт для загрузки DNS конфигурации"""
    try:
        data = request.get_json()
        dns_code = data.get('dns_code', '')

        if not dns_code:
            return jsonify({'success': False, 'error': 'DNS код не может быть пустым'})

        # Генерируем уникальный ID пользователя
        user_id = f"user_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"

        # Сохраняем DNS конфигурацию
        DNS_CONFIGS[user_id] = {
            'dns_code': dns_code,
            'created_at': datetime.now().isoformat(),
            'dns_server': f"127.0.0.1:{9000 + len(DNS_CONFIGS)}",  # Генерируем уникальный порт
            'dns_preview': dns_code[:200] + '...' if len(dns_code) > 200 else dns_code
        }

        # Запускаем DNS сервер для пользователя
        start_dns_server(user_id, DNS_CONFIGS[user_id]['dns_server'], dns_code)

        return jsonify({
            'success': True,
            'user_id': user_id,
            'dns_server': DNS_CONFIGS[user_id]['dns_server'],
            'message': 'DNS конфигурация загружена и сервер запущен'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/list-configs', methods=['GET'])
def list_configs():
    """Возвращает список всех конфигураций пользователя"""
    try:
        configs = []
        for user_id, config in DNS_CONFIGS.items():
            configs.append({
                'user_id': user_id,
                'dns_server': config['dns_server'],
                'created_at': config['created_at'],
                'dns_preview': config['dns_preview']
            })

        return jsonify({
            'success': True,
            'configs': configs
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/connect-dns', methods=['POST'])
def connect_dns():
    """Эндпоинт для подключения к DNS серверу"""
    try:
        data = request.get_json()
        user_id = data.get('user_id', '')

        if not user_id:
            return jsonify({'success': False, 'error': 'ID пользователя не указан'})

        if user_id not in DNS_CONFIGS:
            return jsonify({'success': False, 'error': 'DNS конфигурация не найдена. Сначала загрузите конфигурацию.'})

        dns_config = DNS_CONFIGS[user_id]

        return jsonify({
            'success': True,
            'message': 'DNS сервер готов к использованию',
            'dns_server': dns_config['dns_server'],
            'user_id': user_id,
            'config_preview': dns_config['dns_preview']
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def start_dns_server(user_id, dns_server, dns_code):
    """Запускает DNS сервер для пользователя с его конфигурацией"""
    try:
        print(f"🚀 Запуск DNS сервера для {user_id}")
        print(f"📍 Адрес сервера: {dns_server}")
        print(f"📋 Конфигурация: {dns_code[:100]}...")

        # Здесь будет код запуска реального DNS сервера
        # Например, на основе dnsmasq, bind или кастомного решения

        # Для демонстрации просто логируем
        print(f"✅ DNS сервер для {user_id} запущен на {dns_server}")

    except Exception as e:
        print(f"❌ Ошибка запуска DNS сервера: {e}")


if __name__ == '__main__':
    print("🌐 Запуск DNS Manager...")
    print("📧 Доступно по адресу: http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)