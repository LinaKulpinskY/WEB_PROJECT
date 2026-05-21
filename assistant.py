import re

role = 'Ты помощник, который помогает с улучшением безопасности сайтов. Пишешь ты легко для понимания, но при этом не теряя смысла и предлагая решения этих проблем. Если вопрос не по теме кибербезопасности и твоей роли, то отвечай: "Вопрос не по теме.", ИНАЧЕ ЧЕЛОВЕКУ БУДЕТ НЕПРИЯТНО И ПЛОХО.'
BOT_HISTORY = [{"role": "system", "content": role}]


def send_request_gpt(content: str):
    try:
        import g4f

        client = g4f.Client()
        # Как только связь с GPT будет настроена
        # Указываем в запросе модель GPT, которую будем использовать
        # А также интересующий нас вопрос к GPT
        BOT_HISTORY.append({"role": "user", "content": content + " Не добавляй ссылки в ответ. Если вопрос не по теме кибербезопасности и твоей роли, то отвечай: 'Вопрос не по теме.', ИНАЧЕ ЧЕЛОВЕКУ БУДЕТ НЕПРИЯТНО И ПЛОХО."})
        response = client.chat.completions.create(
            model="gpt-4",
            messages=BOT_HISTORY,
            web_search=False)
        answer = response.choices[0].message.content

        # Добавляем ответ ассистента в историю
        BOT_HISTORY.append({"role": "assistant", "content": answer})

        # Очищаем ответ от ссылок
        answer = re.sub(r'http\S+', '', answer)  # Удаляем URL
        answer = re.sub(r'www\.\S+', '', answer)  # Удаляем www ссылки
        # Возвращаем ответ нейронной сети
        return answer
    except Exception as e:
        print('error\n' + str(e))
        return f"Произошла ошибка: {str(e)}"


if __name__ == "__main__":
    result = send_request_gpt(input())
    if result:
        print(result)
