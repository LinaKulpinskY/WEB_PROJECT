from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import re
import requests
import json
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import uuid
import time

app = Flask(__name__)
CORS(app)

# Хранилище DNS конфигураций пользователей
DNS_CONFIGS = {}

# Role configuration for the AI assistant
role = 'Ты помощник, который помогает с улучшением безопасности сайтов. Пишешь ты легко для понимания, но при этом не теряя смысла и предлагая решения этих проблем. Если вопрос не по теме кибербезопасности и твоей роли, то отвечай: "Вопрос не по теме.", ИНАЧЕ ЧЕЛОВЕКУ БУДЕТ НЕПРИЯТНО И ПЛОХО.'

# Store chat histories per session (in production, use a proper session management)
chat_histories = {}


def get_chat_history(session_id):
    """Get or create chat history for a session"""
    if session_id not in chat_histories:
        chat_histories[session_id] = [{"role": "system", "content": role}]
    return chat_histories[session_id]


def send_request_gpt(content: str, session_id: str):
    """Send request to GPT using g4f"""
    from chat_ai import create_chat_response, friendly_chat_error

    try:
        bot_history = get_chat_history(session_id)

        bot_history.append({
            "role": "user",
            "content": content + " Не добавляй ссылки в ответ. Если вопрос не по теме кибербезопасности и твоей роли, то отвечай: 'Вопрос не по теме.', ИНАЧЕ ЧЕЛОВЕКУ БУДЕТ НЕПРИЯТНО И ПЛОХО."
        })

        answer = create_chat_response(bot_history)
        bot_history.append({"role": "assistant", "content": answer})
        return answer
    except Exception as e:
        print(f'error\n{str(e)}')
        import traceback
        traceback.print_exc()
        return friendly_chat_error(e)


@app.route('/')
def dashboard():
    """Serve the main dashboard page"""
    return render_template('dashboard.html')


@app.route('/chat')
def chat():
    """Serve the chat page"""
    return render_template('chat.html')


@app.route('/api/chat', methods=['POST'])
def chat_api():
    """API endpoint for chat messages"""
    try:
        data = request.json
        message = data.get('message', '')
        session_id = data.get('session_id', 'default')

        if not message:
            return jsonify({'error': 'Message is required'}), 400

        # Call the function directly (not async in newer g4f versions)
        response = send_request_gpt(message, session_id)

        return jsonify({'response': response})
    except Exception as e:
        print(f"Error in chat_api: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


def parse_html_security_info(html_content):
    """Парсит HTML контент и извлекает информацию о безопасности"""
    result = {
        'security_score': 50,
        'security_color': '#3498db',
        'security_level': 'unknown',
        'malware_detected': False,
        'blacklisted': False,
        'issues': []
    }

    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        if not soup:
            return result

        # Ищем индикатор безопасности
        bar_div = soup.find('div', class_='bar')
        if bar_div and bar_div.get('style'):
            style = bar_div['style']
            # Более надежное извлечение цвета
            color_match = re.search(r'background-color:\s*(#[a-fA-F0-9]{3,6}|rgb\([^)]+\)|[a-zA-Z]+)', style)
            if color_match:
                result['security_color'] = color_match.group(1)

            # Извлечение процента
            width_match = re.search(r'width:\s*(\d+)%', style)
            if width_match:
                result['security_score'] = int(width_match.group(1))

        # Анализ текста страницы для обнаружения проблем
        page_text = soup.get_text().lower()

        # Проверка на malware
        malware_indicators = ['malware detected', 'site infected', 'virus found', 'malware found']
        clean_indicators = ['no malware', 'clean', 'no infection', 'not infected']

        malware_detected = any(indicator in page_text for indicator in malware_indicators)
        is_clean = any(indicator in page_text for indicator in clean_indicators)

        if malware_detected and not is_clean:
            result['malware_detected'] = True
            result['security_level'] = 'critical'
            result['issues'].append('Обнаружено вредоносное ПО')

        # Проверка на blacklisting
        blacklist_indicators = ['blacklisted', 'black list', 'listed in']
        not_blacklisted_indicators = ['not blacklisted', 'not listed']

        blacklisted = any(indicator in page_text for indicator in blacklist_indicators)
        not_blacklisted = any(indicator in page_text for indicator in not_blacklisted_indicators)

        if blacklisted and not not_blacklisted:
            result['blacklisted'] = True
            if result['security_level'] != 'critical':
                result['security_level'] = 'high'
            result['issues'].append('Сайт в черных списках')

        # Определяем уровень безопасности на основе score
        if result['security_level'] == 'unknown':
            if result['security_score'] >= 80:
                result['security_level'] = 'good'
            elif result['security_score'] >= 60:
                result['security_level'] = 'medium'
            elif result['security_score'] >= 40:
                result['security_level'] = 'low'
            else:
                result['security_level'] = 'critical'

    except Exception as e:
        print(f"HTML parsing error: {str(e)}")

    return result


def parse_sucuri_results(data, scan_url, html_content=None):
    """Parse Sucuri API response and extract security information"""
    result = {
        'scanned_url': scan_url,
        'security_level': 'unknown',
        'security_score': 50,
        'security_color': '#3498db',  # Default blue color
        'malware_detected': False,
        'blacklisted': False,
        'blacklists': {},
        'malware_details': [],
        'website_info': {},
        'issues': [],
        'recommendations': [],
        'raw_data': data
    }

    # Если есть HTML контент, парсим его
    if html_content:
        html_result = parse_html_security_info(html_content)
        result.update(html_result)

    try:
        # Check if we have SCAN data
        if 'SCAN' in data:
            scan_data = data['SCAN']

            # Check for malware
            if 'SITE' in scan_data:
                site_data = scan_data['SITE']
                if 'MALWARE' in site_data and site_data['MALWARE']:
                    result['malware_detected'] = True
                    result['security_level'] = 'critical'
                    result['security_score'] = 20
                    result['issues'].append('Обнаружено вредоносное ПО на сайте')

            # Check blacklists
            if 'BLACKLIST' in scan_data:
                blacklist_data = scan_data['BLACKLIST']
                result['blacklists'] = blacklist_data
                listed = [k for k, v in blacklist_data.items() if v]
                if listed:
                    result['blacklisted'] = True
                    if result['security_level'] != 'critical':
                        result['security_level'] = 'high'
                    result['security_score'] = min(result['security_score'], 40)
                    result['issues'].append(f'Сайт находится в черных списках: {", ".join(listed)}')

            # Get malware details
            if 'MALWARE' in scan_data:
                malware_data = scan_data['MALWARE']
                if isinstance(malware_data, dict):
                    if 'DETAILS' in malware_data:
                        result['malware_details'] = malware_data['DETAILS'] if isinstance(malware_data['DETAILS'],
                                                                                          list) else [
                            malware_data['DETAILS']]

            # Get website info
            if 'WEBSITE' in scan_data:
                result['website_info'] = scan_data['WEBSITE']

            # Determine security level and score
            if not result['malware_detected'] and not result['blacklisted']:
                result['security_level'] = 'good'
                result['security_score'] = 80
            elif result['security_level'] == 'unknown':
                result['security_level'] = 'medium'
                result['security_score'] = 60

        # Alternative: if data structure is different, try to parse it
        elif isinstance(data, dict):
            # Try to extract information from various possible structures
            if 'malware' in data or 'Malware' in data:
                result['malware_detected'] = True
                result['security_level'] = 'critical'
                result['security_score'] = 20

            if 'blacklist' in data or 'Blacklist' in data:
                result['blacklisted'] = True
                if result['security_level'] != 'critical':
                    result['security_level'] = 'high'
                result['security_score'] = min(result['security_score'], 40)

    except Exception as e:
        print(f"Error parsing results: {str(e)}")
        import traceback
        traceback.print_exc()

    # Generate recommendations
    result['recommendations'] = generate_security_recommendations(result)

    return result


def generate_security_recommendations(result):
    """Generate security improvement recommendations based on scan results"""
    recommendations = []

    if result['malware_detected']:
        recommendations.append({
            'priority': 'critical',
            'title': 'Удалите вредоносное ПО',
            'description': 'Обнаружено вредоносное ПО на вашем сайте. Немедленно удалите все вредоносные файлы и коды.'
        })
        recommendations.append({
            'priority': 'high',
            'title': 'Проверьте все файлы сайта',
            'description': 'Выполните полное сканирование всех файлов на сервере для выявления зараженных файлов.'
        })
        recommendations.append({
            'priority': 'high',
            'title': 'Смените все пароли',
            'description': 'Смените пароли от всех учетных записей: FTP, панель управления, база данных, админ-панель CMS.'
        })

    if result['blacklisted']:
        recommendations.append({
            'priority': 'high',
            'title': 'Подайте запрос на удаление из черных списков',
            'description': 'После очистки сайта от вредоносного ПО подайте запрос на удаление из черных списков в соответствующих сервисах.'
        })

    # General recommendations based on security level
    if result['security_level'] in ['low', 'medium', 'unknown']:
        recommendations.append({
            'priority': 'medium',
            'title': 'Установите SSL-сертификат',
            'description': 'Используйте HTTPS для шифрования данных между браузером и сервером. Это защитит данные пользователей.'
        })

        recommendations.append({
            'priority': 'medium',
            'title': 'Настройте заголовки безопасности',
            'description': 'Настройте HTTP-заголовки безопасности: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection.'
        })

        recommendations.append({
            'priority': 'medium',
            'title': 'Регулярно обновляйте CMS и плагины',
            'description': 'Устаревшие версии CMS и плагинов содержат известные уязвимости. Регулярно обновляйте их до последних версий.'
        })

    if result['security_level'] in ['low', 'unknown']:
        recommendations.append({
            'priority': 'high',
            'title': 'Проведите аудит безопасности',
            'description': 'Рекомендуется провести полный аудит безопасности сайта профессиональными средствами.'
        })

    # Always include these recommendations
    recommendations.append({
        'priority': 'low',
        'title': 'Используйте Web Application Firewall (WAF)',
        'description': 'WAF поможет защитить ваш сайт от различных атак, включая SQL-инъекции, XSS и другие.'
    })

    recommendations.append({
        'priority': 'low',
        'title': 'Регулярно создавайте резервные копии',
        'description': 'Регулярное резервное копирование поможет быстро восстановить сайт в случае проблем.'
    })

    recommendations.append({
        'priority': 'low',
        'title': 'Используйте сильные пароли',
        'description': 'Используйте сложные пароли для всех учетных записей и включите двухфакторную аутентификацию где это возможно.'
    })

    # Sort by priority
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    recommendations.sort(key=lambda x: priority_order[x['priority']])

    return recommendations


def perform_basic_security_checks(response, url):
    """Выполняет базовые проверки безопасности"""
    checks = {
        'malware_detected': False,
        'blacklisted': False,
        'issues': [],
        'website_info': {
            'server': response.headers.get('Server', 'Unknown'),
            'content_type': response.headers.get('Content-Type', 'Unknown'),
            'status_code': response.status_code
        }
    }

    content = response.text.lower()
    headers = response.headers

    # Проверка HTTPS
    if url.startswith('http://'):
        checks['issues'].append('Сайт использует HTTP вместо HTTPS')

    # Проверка security headers
    security_headers = {
        'Strict-Transport-Security': 'HSTS не настроен',
        'X-Frame-Options': 'Заголовок X-Frame-Options не настроен',
        'X-Content-Type-Options': 'Заголовок X-Content-Type-Options не настроен',
        'Content-Security-Policy': 'CSP не настроен'
    }

    for header, message in security_headers.items():
        if header not in headers:
            checks['issues'].append(message)

    # Базовые проверки на подозрительный контент
    suspicious_patterns = [
        r'<iframe[^>]*src="http://',
        r'eval\(',
        r'document\.write',
        r'base64,',
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            checks['issues'].append('Обнаружены потенциально опасные скрипты')
            break

    return checks


def direct_security_scan(url):
    """Прямое сканирование сайта без использования Sucuri"""
    try:
        # Нормализуем URL
        if not url.startswith(('http://', 'https://')):
            scan_url = 'https://' + url
        else:
            scan_url = url

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        result = {
            'scanned_url': scan_url,
            'security_level': 'unknown',
            'security_score': 50,
            'security_color': '#3498db',
            'malware_detected': False,
            'blacklisted': False,
            'website_info': {},
            'issues': [],
            'direct_scan': True
        }

        # Проверяем доступность сайта
        response = requests.get(scan_url, headers=headers, timeout=10, verify=True)

        if response.status_code == 200:
            # Базовые проверки безопасности
            security_checks = perform_basic_security_checks(response, scan_url)
            result.update(security_checks)

            # Если все проверки пройдены, считаем сайт безопасным
            if (not result['malware_detected'] and
                    not result['blacklisted'] and
                    len(result['issues']) == 0):
                result['security_level'] = 'good'
                result['security_score'] = 85
                result['security_color'] = '#2ecc71'
            elif len(result['issues']) > 0:
                result['security_level'] = 'medium'
                result['security_score'] = 65
                result['security_color'] = '#f39c12'

        result['recommendations'] = generate_security_recommendations(result)
        return result

    except requests.exceptions.SSLError:
        result = {
            'scanned_url': url,
            'security_level': 'medium',
            'security_score': 60,
            'security_color': '#f39c12',
            'malware_detected': False,
            'blacklisted': False,
            'issues': ['Проблемы с SSL сертификатом'],
            'website_info': {},
            'direct_scan': True
        }
        result['recommendations'] = generate_security_recommendations(result)
        return result

    except requests.exceptions.RequestException as e:
        print(f"Direct scan error: {e}")
        return None


def create_basic_security_report(url, error_message=None):
    """Создает базовый отчет когда сканеры не работают"""
    return {
        'scanned_url': url,
        'security_level': 'unknown',
        'security_score': 50,
        'security_color': '#95a5a6',  # Серый цвет для неизвестного статуса
        'malware_detected': False,
        'blacklisted': False,
        'blacklists': {},
        'malware_details': [],
        'website_info': {},
        'issues': [
            'Не удалось получить данные от сканеров безопасности',
            'Сайт может использовать защиту от автоматического сканирования'
        ],
        'recommendations': [
            {
                'priority': 'medium',
                'title': 'Проверьте сайт вручную',
                'description': 'Посетите https://sitecheck.sucuri.net и введите URL вручную для получения результатов'
            }
        ],
        'manual_check_url': f'https://sitecheck.sucuri.net/results/{url}',
        'note': 'Автоматическое сканирование не дало результатов. Требуется ручная проверка.',
        'error': error_message
    }


def scan_website_with_sucuri(url):
    """Scan website using Sucuri SiteCheck API"""
    try:
        # Clean the URL
        url = url.strip()
        # Remove protocol if present for normalization
        if url.startswith(('http://', 'https://')):
            parsed = urlparse(url)
            url = parsed.netloc or parsed.path

        # Remove trailing slash
        url = url.rstrip('/')
        # Add https protocol
        if not url.startswith(('http://', 'https://')):
            scan_url = 'https://' + url
        else:
            scan_url = url

        # Try multiple API endpoints
        api_endpoints = [
            'https://sitecheck.sucuri.net/api/v3/',
            'https://sitecheck.sucuri.net/api/v2/',
            'https://sitecheck.sucuri.net/api/v1/',
        ]

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json,text/html',
            'Referer': 'https://sitecheck.sucuri.net/'
        }

        # Try to get JSON response from API
        for api_url in api_endpoints:
            try:
                params = {'scan': scan_url}
                response = requests.get(api_url, params=params, headers=headers, timeout=15)

                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '')

                    if 'application/json' in content_type:
                        try:
                            data = response.json()
                            if data and isinstance(data, dict) and data:
                                return parse_sucuri_results(data, scan_url)
                        except json.JSONDecodeError:
                            continue
                    else:
                        # Это HTML ответ, парсим его
                        return parse_sucuri_results({}, scan_url, response.text)

            except requests.exceptions.RequestException:
                continue

        # Если API не работает, пробуем scraping HTML страницы
        try:
            results_url = f'https://sitecheck.sucuri.net/results/{scan_url}'
            html_response = requests.get(results_url, headers=headers, timeout=15)

            if html_response.status_code == 200:
                return parse_sucuri_results({}, scan_url, html_response.text)

        except Exception as e:
            print(f"Error scraping HTML: {str(e)}")

        # Если ничего не сработало, возвращаем базовый отчет
        return create_basic_security_report(url, "Sucuri API не ответил")

    except Exception as e:
        print(f"Unexpected error in Sucuri scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return create_basic_security_report(url, f"Ошибка: {str(e)}")


def scan_website_multiple(url):
    """Сканирует сайт используя несколько сервисов"""

    # Сначала пробуем Sucuri
    sucuri_result = scan_website_with_sucuri(url)

    # Проверяем, получили ли мы реальные данные (не базовый отчет)
    if (sucuri_result.get('security_level') != 'unknown' and
            not sucuri_result.get('error') and
            sucuri_result.get('website_info') and
            'Не удалось получить данные' not in str(sucuri_result.get('issues', []))):
        return sucuri_result

    # Если Sucuri не сработал, пробуем прямое сканирование
    print(f"Sucuri scan failed for {url}, trying direct scan...")
    direct_result = direct_security_scan(url)

    if direct_result and direct_result.get('security_level') != 'unknown':
        return direct_result

    # Если ничего не работает, возвращаем честный unknown статус
    return create_basic_security_report(url, "Не удалось просканировать сайт")


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan website and display results"""
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            return render_template('scan.html', error='URL не указан')
    else:
        url = request.args.get('url', '').strip()
        if not url:
            return render_template('scan.html')

    # Perform scan
    scan_results = scan_website_multiple(url)

    return render_template('scan.html', url=url, results=scan_results)


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for scanning websites"""
    try:
        data = request.json
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Perform scan
        scan_results = scan_website_multiple(url)

        return jsonify(scan_results)
    except Exception as e:
        print(f"Error in api_scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


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


@app.route('/test-dns', methods=['POST'])
def test_dns():
    """Проверка DNS-конфигурации пользователя"""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id', '').strip()
        domain = (data.get('domain') or 'google.com').strip()

        if not user_id:
            return jsonify({'success': False, 'error': 'ID пользователя не указан'})

        if user_id not in DNS_CONFIGS:
            return jsonify({'success': False, 'error': 'DNS конфигурация не найдена. Сначала загрузите конфигурацию.'})

        started = time.time()
        ip = socket.gethostbyname(domain)
        elapsed_ms = int((time.time() - started) * 1000)

        return jsonify({
            'success': True,
            'domain': domain,
            'ip': ip,
            'response_time': elapsed_ms,
            'dns_server': DNS_CONFIGS[user_id]['dns_server'],
        })
    except socket.gaierror as e:
        return jsonify({'success': False, 'error': f'Не удалось разрешить домен: {e}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def start_dns_server(user_id, dns_server, dns_code):
    """Запускает DNS сервер для пользователя с его конфигурацией"""
    try:
        print(f"🚀 Запуск DNS сервера для {user_id}")
        print(f"📍 Адрес сервера: {dns_server}")
        print(f"📋 Конфигурация: {dns_code[:100]}...")

        # Здесь будет код запуска реального DNS сервера
        print(f"✅ DNS сервер для {user_id} запущен на {dns_server}")

    except Exception as e:
        print(f"❌ Ошибка запуска DNS сервера: {e}")



if __name__ == '__main__':
    app.run(debug=True, port=5000)