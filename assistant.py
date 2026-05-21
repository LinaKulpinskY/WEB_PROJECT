from chat_ai import create_chat_response, friendly_chat_error

role = 'Ты помощник, который помогает с улучшением безопасности сайтов. Пишешь ты легко для понимания, но при этом не теряя смысла и предлагая решения этих проблем. Если вопрос не по теме кибербезопасности и твоей роли, то отвечай: "Вопрос не по теме.", ИНАЧЕ ЧЕЛОВЕКУ БУДЕТ НЕПРИЯТНО И ПЛОХО.'
BOT_HISTORY = [{"role": "system", "content": role}]


def send_request_gpt(content: str):
    try:
        BOT_HISTORY.append({
            "role": "user",
            "content": content + " Не добавляй ссылки в ответ. Если вопрос не по теме кибербезопасности и твоей роли, то отвечай: 'Вопрос не по теме.', ИНАЧЕ ЧЕЛОВЕКУ БУДЕТ НЕПРИЯТНО И ПЛОХО."
        })
        answer = create_chat_response(BOT_HISTORY)
        BOT_HISTORY.append({"role": "assistant", "content": answer})
        return answer
    except Exception as e:
        print('error\n' + str(e))
        return friendly_chat_error(e)


if __name__ == "__main__":
    result = send_request_gpt(input())
    if result:
        print(result)
