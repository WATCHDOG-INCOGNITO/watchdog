from rest_framework.response import Response


def ok(data=None, meta=None, http_status=200):
    return Response(
        {"data": data, "meta": meta or {}, "error": None},
        status=http_status,
    )


def fail(code: str, message: str, meta=None, http_status=400):
    return Response(
        {"data": None, "meta": meta or {}, "error": {"code": code, "message": message}},
        status=http_status,
    )
