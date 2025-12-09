from flask import Flask, render_template, request, jsonify
import dns.resolver
import dns.rdatatype
import logging
from typing import Dict, List, Any

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


class DNSAnalyzer:
    """Класс для анализа DNS-записей домена"""

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        # Настройка таймаутов и повторных попыток
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """
        Получает все DNS-записи для указанного домена

        Args:
            domain (str): Доменное имя для анализа

        Returns:
            Dict: Словарь с DNS-записями и информацией об ошибками
        """
        records = {}
        errors = []

        # Список типов записей для проверки
        record_types = [
            ('A', 'A-записи (IPv4-адреса)'),
            ('AAAA', 'AAAA-записи (IPv6-адреса)'),
            ('MX', 'MX-записи (почтовые серверы)'),
            ('CNAME', 'CNAME-записи (канонические имена)'),
            ('NS', 'NS-записи (серверы имён)'),
            ('TXT', 'TXT-записи (текстовые записи)'),
            ('SOA', 'SOA-запись (информация о зоне)')
        ]

        for rtype, description in record_types:
            try:
                logger.info(f"Запрос {rtype} записей для {domain}")

                if rtype == 'SOA':
                    # SOA запись обрабатывается отдельно
                    answers = self.resolver.resolve(domain, rtype)
                    records[rtype] = self._parse_soa_record(answers)
                else:
                    answers = self.resolver.resolve(domain, rtype)
                    records[rtype] = self._parse_records(answers, rtype)

            except dns.resolver.NoAnswer:
                # Нет записей этого типа - это нормально
                records[rtype] = []
                logger.info(f"Нет {rtype} записей для {domain}")
            except dns.resolver.NXDOMAIN:
                error_msg = f"Домен {domain} не существует"
                errors.append(error_msg)
                logger.error(error_msg)
                break
            except dns.resolver.Timeout:
                error_msg = f"Таймаут при запросе {rtype} записей"
                errors.append(error_msg)
                logger.error(error_msg)
            except dns.resolver.NoNameservers:
                error_msg = "Не удалось найти серверы имён для домена"
                errors.append(error_msg)
                logger.error(error_msg)
                break
            except Exception as e:
                error_msg = f"Ошибка при получении {rtype} записей: {str(e)}"
                errors.append(error_msg)
                logger.error(error_msg)

        return {
            'domain': domain,
            'records': records,
            'errors': errors,
            'success': len(errors) == 0
        }

    def _parse_records(self, answers: dns.resolver.Answer, rtype: str) -> List[Dict]:
        """Парсит DNS-ответы в структурированный формат"""
        parsed_records = []

        # TTL берется из ответа, а не из отдельных записей
        response_ttl = answers.rrset.ttl if answers.rrset else 300

        for answer in answers:
            record_data = {
                'value': self._format_record_value(answer, rtype),
                'ttl': response_ttl
            }

            # Специфичная обработка для разных типов записей
            if rtype == 'MX':
                record_data['preference'] = answer.preference
                record_data['exchange'] = str(answer.exchange)
                record_data['value'] = f"Приоритет: {answer.preference} -> {answer.exchange}"

            elif rtype == 'TXT':
                # TXT записи могут содержать несколько строк
                if isinstance(answer.strings, list) and len(answer.strings) > 0:
                    # Объединяем все строки TXT записи
                    txt_value = ' '.join([s.decode('utf-8') for s in answer.strings])
                    record_data['value'] = txt_value

            parsed_records.append(record_data)

        return parsed_records

    def _format_record_value(self, answer, rtype: str) -> str:
        """Форматирует значение записи в зависимости от типа"""
        if rtype == 'A':
            return str(answer.address)
        elif rtype == 'AAAA':
            return str(answer.address)
        elif rtype == 'CNAME':
            return str(answer.target)
        elif rtype == 'NS':
            return str(answer.target)
        elif rtype == 'TXT':
            if hasattr(answer, 'strings'):
                return ' '.join([s.decode('utf-8') for s in answer.strings])
            return str(answer)
        else:
            return str(answer)

    def _parse_soa_record(self, answers: dns.resolver.Answer) -> List[Dict]:
        """Парсит SOA запись в детализированный формат"""
        parsed_records = []

        # TTL берется из ответа
        response_ttl = answers.rrset.ttl if answers.rrset else 3600

        for answer in answers:
            soa_data = {
                'mname': str(answer.mname),  # Primary nameserver
                'rname': str(answer.rname),  # Administrator email
                'serial': answer.serial,  # Zone serial number
                'refresh': answer.refresh,  # Refresh interval
                'retry': answer.retry,  # Retry interval
                'expire': answer.expire,  # Expire time
                'minimum': answer.minimum,  # Minimum TTL
                'ttl': response_ttl
            }

            # Форматируем значение для отображения
            soa_data['value'] = (
                f"Основной NS: {soa_data['mname']}\n"
                f"Email администратора: {soa_data['rname']}\n"
                f"Серийный номер: {soa_data['serial']}\n"
                f"Обновление: {soa_data['refresh']} сек\n"
                f"Повтор: {soa_data['retry']} сек\n"
                f"Истечение: {soa_data['expire']} сек\n"
                f"Минимальный TTL: {soa_data['minimum']} сек"
            )

            parsed_records.append(soa_data)

        return parsed_records


# Создаем экземпляр анализатора
dns_analyzer = DNSAnalyzer()


@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')


@app.route('/api/dns-records', methods=['POST'])
def get_dns_records():
    """API endpoint для получения DNS-записей"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()

        if not domain:
            return jsonify({
                'success': False,
                'error': 'Не указано доменное имя'
            }), 400

        # Убедимся, что домен правильно отформатирован
        if not domain.startswith('www.') and '.' in domain:
            # Убираем возможные протоколы
            domain = domain.replace('http://', '').replace('https://', '')

        logger.info(f"Запрос DNS-записей для домена: {domain}")

        # Получаем DNS-записи
        result = dns_analyzer.get_dns_records(domain)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Ошибка при обработке запроса: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Внутренняя ошибка сервера: {str(e)}'
        }), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Страница не найдена'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Внутренняя ошибка сервера'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)