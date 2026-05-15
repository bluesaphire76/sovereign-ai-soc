def strip_think_blocks(text: str | None) -> str:
    if not text:
        return ""

    cleaned = str(text)

    while True:
        lowered = cleaned.lower()
        start = lowered.find("<think")
        if start == -1:
            break

        end = lowered.find("</think>", start)

        if end == -1:
            cleaned = cleaned[:start]
            break

        cleaned = cleaned[:start] + cleaned[end + len("</think>"):]

    cleaned = cleaned.replace("<think>", "")
    cleaned = cleaned.replace("</think>", "")

    return cleaned.strip()


def contains_cjk(text: str | None) -> bool:
    if not text:
        return False

    for char in text:
        if (
            "\u4e00" <= char <= "\u9fff" or
            "\u3040" <= char <= "\u30ff" or
            "\uac00" <= char <= "\ud7af"
        ):
            return True

    return False


def is_invalid_llm_output(text: str | None) -> bool:
    if not text:
        return True

    lowered = text.lower()

    return (
        "<think" in lowered or
        "</think>" in lowered or
        contains_cjk(text)
    )


def sanitize_llm_output(text: str | None) -> str:
    return strip_think_blocks(text)
