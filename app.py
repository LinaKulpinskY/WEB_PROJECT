from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS
import g4f
import re
import requests
import json
from urllib.parse import quote, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template_string
import json
import os
import subprocess
from datetime import datetime
import uuid

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
    try:
        BOT_HISTORY = get_chat_history(session_id)
        
        # Create client for GPT API
        client = g4f.Client()
        
        # Add user message to history
        BOT_HISTORY.append({
            "role": "user", 
            "content": content + " Не добавляй ссылки в ответ. Если вопрос не по теме кибербезопасности и твоей роли, то отвечай: 'Вопрос не по теме.', ИНАЧЕ ЧЕЛОВЕКУ БУДЕТ НЕПРИЯТНО И ПЛОХО."
        })
        
        # Get response from GPT
        response = client.chat.completions.create(
            model="gpt-4",
            messages=BOT_HISTORY,
            web_search=False
        )
        
        answer = response.choices[0].message.content
        
        # Add assistant response to history
        BOT_HISTORY.append({"role": "assistant", "content": answer})
        
        # Clean answer from links
        answer = re.sub(r'http\S+', '', answer)  # Remove URLs
        answer = re.sub(r'www\.\S+', '', answer)  # Remove www links
        
        return answer
    except Exception as e:
        print(f'error\n{str(e)}')
        import traceback
        traceback.print_exc()
        return f"Произошла ошибка: {str(e)}"

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

def parse_sucuri_results(data, scan_url, html_content=None):
    """Parse Sucuri API response and extract security information"""
    result = {
        'scanned_url': scan_url,
        'security_level': 'unknown',
        'security_score': 0,
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
    
    # Try to extract color from HTML if provided
    if html_content:
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            # Find div with class "bar"
            bar_div = soup.find('div', class_='bar')
            if bar_div:
                style = bar_div.get('style', '')
                # Extract background-color from style attribute
                import re
                color_match = re.search(r'background-color:\s*([^;]+)', style)
                if color_match:
                    result['security_color'] = color_match.group(1).strip()
                    # Also try to extract width if available
                    width_match = re.search(r'width:\s*(\d+)%', style)
                    if width_match:
                        result['security_score'] = int(width_match.group(1))
        except Exception as e:
            print(f"Error extracting color from HTML: {str(e)}")
    
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
                        result['malware_details'] = malware_data['DETAILS'] if isinstance(malware_data['DETAILS'], list) else [malware_data['DETAILS']]
            
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
            
            # Generate recommendations
            result['recommendations'] = generate_security_recommendations(result)
            
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
            
            result['recommendations'] = generate_security_recommendations(result)
        
    except Exception as e:
        print(f"Error parsing results: {str(e)}")
        import traceback
        traceback.print_exc()
    
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
    
    # General recommendations
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
    
    return recommendations

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
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json'
        }
        
        # Try to get JSON response from API
        for api_url in api_endpoints:
            try:
                params = {'scan': scan_url}
                response = requests.get(api_url, params=params, headers=headers, timeout=60)
                response.raise_for_status()
                
                # Try to parse as JSON
                try:
                    data = response.json()
                    if data:
                        # Check if JSON contains HTML string
                        html_content = None
                        if isinstance(data, dict):
                            # Look for HTML content in various possible keys
                            for key in ['html', 'content', 'body', 'result', 'data']:
                                if key in data and isinstance(data[key], str) and '<div' in data[key]:
                                    html_content = data[key]
                                    break
                        return parse_sucuri_results(data, scan_url, html_content)
                except json.JSONDecodeError:
                    # If not JSON, save content for HTML parsing
                    html_content = response.text
                    return parse_sucuri_results({}, scan_url, html_content)
            except:
                continue
        
        # If API doesn't work, try scraping the HTML results page
        try:
            results_url = f'https://sitecheck.sucuri.net/results/{scan_url}'
            html_response = requests.get(results_url, headers=headers, timeout=60)
            html_response.raise_for_status()
            
            # Parse HTML to extract information
            html_content = html_response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Try to extract security information from HTML
            result = {
                'scanned_url': scan_url,
                'security_level': 'unknown',
                'security_score': 50,
                'security_color': '#3498db',  # Default blue
                'malware_detected': False,
                'blacklisted': False,
                'blacklists': {},
                'malware_details': [],
                'website_info': {},
                'issues': [],
                'recommendations': generate_security_recommendations({
                    'malware_detected': False,
                    'blacklisted': False,
                    'security_level': 'unknown'
                }),
                'html_source': True,
                'sucuri_url': results_url
            }
            
            # Look for the bar div with security indicator
            bar_div = soup.find('div', class_='bar')
            if bar_div:
                style = bar_div.get('style', '')
                # Extract background-color from style
                import re
                color_match = re.search(r'background-color:\s*([^;]+)', style)
                if color_match:
                    result['security_color'] = color_match.group(1).strip()
                # Extract width percentage
                width_match = re.search(r'width:\s*(\d+)%', style)
                if width_match:
                    result['security_score'] = int(width_match.group(1))
            
            # Look for malware indicators
            page_text = soup.get_text().lower()
            if 'malware' in page_text or 'infected' in page_text or 'virus' in page_text:
                if 'no malware' not in page_text and 'clean' not in page_text:
                    result['malware_detected'] = True
                    result['security_level'] = 'critical'
                    if result['security_score'] > 20:
                        result['security_score'] = 20
            
            # Look for blacklist indicators
            if 'blacklisted' in page_text or 'black list' in page_text:
                result['blacklisted'] = True
                if result['security_level'] != 'critical':
                    result['security_level'] = 'high'
                if result['security_score'] > 40:
                    result['security_score'] = min(result['security_score'], 40)
            
            # Update recommendations based on findings
            result['recommendations'] = generate_security_recommendations(result)
            
            return result
            
        except Exception as e:
            print(f"Error scraping HTML: {str(e)}")
        
        # Fallback: return basic structure with recommendations
        return {
            'scanned_url': scan_url,
            'security_level': 'unknown',
            'security_score': 50,
            'security_color': '#3498db',  # Default blue
            'malware_detected': False,
            'blacklisted': False,
            'blacklists': {},
            'malware_details': [],
            'website_info': {},
            'issues': ['Не удалось получить результаты от Sucuri SiteCheck API'],
            'recommendations': generate_security_recommendations({
                'malware_detected': False,
                'blacklisted': False,
                'security_level': 'unknown'
            }),
            'note': 'Результаты сканирования могут быть неполными. Рекомендуется проверить сайт напрямую на sitecheck.sucuri.net',
            'sucuri_url': f'https://sitecheck.sucuri.net/results/{scan_url}'
        }
        
    except requests.exceptions.RequestException as e:
        print(f"Error scanning website: {str(e)}")
        return {
            'error': f'Ошибка при сканировании: {str(e)}',
            'scanned_url': scan_url if 'scan_url' in locals() else url,
            'security_color': '#3498db',
            'recommendations': generate_security_recommendations({
                'malware_detected': False,
                'blacklisted': False,
                'security_level': 'unknown'
            })
        }
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'error': f'Неожиданная ошибка: {str(e)}',
            'scanned_url': scan_url if 'scan_url' in locals() else url,
            'security_color': '#3498db',
            'recommendations': generate_security_recommendations({
                'malware_detected': False,
                'blacklisted': False,
                'security_level': 'unknown'
            })
        }

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
            return render_template('scan.html', error='URL не указан')
    
    # Perform scan
    scan_results = scan_website_with_sucuri(url)
    
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
        scan_results = scan_website_with_sucuri(url)
        
        return jsonify(scan_results)
    except Exception as e:
        print(f"Error in api_scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

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
    app.run(debug=True, port=5000)

