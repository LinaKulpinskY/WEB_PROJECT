import os
import re

DEFAULT_PROVIDER = "PollinationsAI"
FALLBACK_MODELS = ("openai-large", "mistral", "openai")


def _sanitize(answer: str) -> str:
    answer = re.sub(r"http\S+", "", answer)
    answer = re.sub(r"www\.\S+", "", answer)
    return answer.strip()


def _is_unusable_response(text: str) -> bool:
    if not text or not text.strip():
        return True
    stripped = text.lstrip()
    if stripped.startswith("<!DOCTYPE") or stripped.startswith("<html"):
        return True
    lower = text.lower()
    if "important notice" in lower and "pollinations" in lower:
        return True
    if "retryprovider failed" in lower:
        return True
    return False


def friendly_chat_error(exc: Exception) -> str:
    message = str(exc)
    lower = message.lower()
    if "request limit" in lower or "rate limit" in lower:
        return (
            "Сервис AI временно ограничил число запросов. "
            "Подождите минуту и попробуйте снова."
        )
    if "retryprovider failed" in lower:
        return (
            "Сейчас недоступны бесплатные AI-сервисы. "
            "Повторите через минуту или задайте переменную окружения OPENAI_API_KEY."
        )
    if "no .har file" in lower:
        return (
            "Для этого провайдера нужна авторизация. "
            "Задайте OPENAI_API_KEY или повторите попытку позже."
        )
    return f"Произошла ошибка: {message}"


def create_chat_response(messages: list) -> str:
    """Send messages to an AI provider and return the assistant reply."""
    import g4f
    from g4f import Client

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if api_key:
        client = Client(api_key=api_key)
        models = [os.environ.get("OPENAI_MODEL", "gpt-4o-mini")]
    else:
        provider = os.environ.get("G4F_CHAT_PROVIDER", DEFAULT_PROVIDER)
        client = Client(provider=provider)
        models = FALLBACK_MODELS

    last_error = None
    for model in models:
        try:
            response = client.chat.completions.create(model=model, messages=messages)
            answer = response.choices[0].message.content or ""
            if not _is_unusable_response(answer):
                return _sanitize(answer)
        except Exception as exc:
            last_error = exc

    if last_error is not None:
        raise last_error
    raise RuntimeError("Пустой ответ от AI")
