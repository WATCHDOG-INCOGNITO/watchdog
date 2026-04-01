from __future__ import annotations


def flatten_exception_messages(exc: BaseException) -> list[str]:
    messages: list[str] = []
    visited: set[int] = set()

    def visit(err: BaseException | None) -> None:
        if err is None:
            return

        err_id = id(err)
        if err_id in visited:
            return
        visited.add(err_id)

        if isinstance(err, BaseExceptionGroup):
            for sub_exc in err.exceptions:
                visit(sub_exc)
            return

        message = str(err).strip()
        label = f"{err.__class__.__name__}: {message}" if message else err.__class__.__name__
        if label not in messages:
            messages.append(label)

        cause = getattr(err, "__cause__", None)
        context = getattr(err, "__context__", None)
        visit(cause)
        if context is not cause:
            visit(context)

    visit(exc)
    return messages


def summarize_exception(exc: BaseException, limit: int = 2000) -> str:
    messages = flatten_exception_messages(exc)
    if not messages:
        return exc.__class__.__name__
    return " | ".join(messages)[:limit]
