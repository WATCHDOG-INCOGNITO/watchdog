"""Source code reading 도구 — white-box / glass-box CTF용 일반 능력.

CodeGate finals 같은 source 제공형 문제는 black-box endpoint scan만으로는 풀 수 없다.
이 모듈은 *임의의 코드 디렉터리*를 안전하게 탐색·읽기·검색할 수 있게 한다 — 특정 문제에
하드코딩된 게 아니라, 어떤 source tree든 동일하게 동작.

마운트 root는 환경변수 `SOURCE_ROOTS` 로 지정 (콜론 구분, 화이트리스트). 기본값
`/sources`. 각 호출은 root 안으로 제한 (path traversal 차단).

도구 3개 (모두 read-only):
  - list_source_tree(root, max_depth, glob)
  - read_source(path, start_line, end_line)  — 큰 파일 부분 읽기
  - grep_source(pattern, root, glob, flags) — 정규식 검색
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

# ── 안전 root 화이트리스트 ─────────────────────────────────
DEFAULT_ROOTS = ["/sources"]
SOURCE_ROOTS = [
    Path(p).resolve()
    for p in os.environ.get("SOURCE_ROOTS", ":".join(DEFAULT_ROOTS)).split(":")
    if p.strip()
]
MAX_FILE_BYTES = 1_000_000   # 1MB 하나의 read 상한
MAX_TREE_ENTRIES = 2000
MAX_GREP_MATCHES = 200

# CTF 채점 안전망 — 정답/flag 포함 디렉터리/파일은 읽기 차단.
# 여러 대회가 bulk mount되지만 이 필터가 에이전트 접근을 for_user/*만 허용.
FORBIDDEN_PATH_TOKENS = (
    "for_organizer",     # 출제자용 (풀이, flag 포함)
    "/exploit/",         # 정답 exploit
    "/exploit.md",
    "/exploit.py",
    "/anticheat/",       # 채점 모듈 (dynamic flag)
    "/flag.txt",         # 플래그 파일
    "/flag",
    "info.yaml",         # flag 메타데이터 포함
)
# 대회 root 바로 아래 README.md는 출제자 풀이 가능성 → 차단.
# for_user 안의 README 또는 source 파일은 허용 (참가자 문서).
REQUIRED_PATH_SUBSTRING = "/for_user"


def _resolve_safe(p: str) -> Path | None:
    """안전 root + for_user 경로 + 금지 토큰 미포함이면 Path 반환, 아니면 None."""
    if not p:
        return None
    try:
        candidate = Path(p).expanduser().resolve()
    except Exception:
        return None
    s = str(candidate).replace("\\", "/")
    # 금지 토큰 차단 (정답/flag 노출 방지)
    if any(tok in s for tok in FORBIDDEN_PATH_TOKENS):
        return None
    # CTF 대회 mount(`/sources/codegate*`)에 속하면 반드시 for_user 경로 포함
    for root in SOURCE_ROOTS:
        try:
            rel = candidate.relative_to(root)
            rel_str = str(rel).replace("\\", "/")
            # 대회 디렉터리 아래는 for_user 경로 필수, 디렉터리 자체는 허용
            if rel_str and "codegate" in rel_str.split("/", 1)[0].lower():
                # for_user 경로 미포함이면 차단 (대회 디렉터리 또는 문제 디렉터리까지만 목록은 허용)
                depth = len(rel.parts)
                if depth >= 4 and REQUIRED_PATH_SUBSTRING not in "/" + rel_str:
                    return None
            return candidate
        except ValueError:
            continue
    return None


def _list_tree(root_path: str, max_depth: int, glob: str) -> dict:
    base = _resolve_safe(root_path or str(SOURCE_ROOTS[0]) if SOURCE_ROOTS else "")
    if base is None or not base.exists():
        return {
            "error": (
                f"root '{root_path}' 가 SOURCE_ROOTS({[str(r) for r in SOURCE_ROOTS]})"
                f" 안에 없거나 존재하지 않음"
            ),
        }
    if not base.is_dir():
        return {"error": f"{base} 는 디렉터리가 아님"}

    pattern = (glob or "**/*").strip()
    entries: list[dict] = []
    try:
        for path in base.glob(pattern):
            try:
                rel = path.relative_to(base)
            except ValueError:
                continue
            path_str = str(path).replace("\\", "/")
            if any(tok in path_str for tok in FORBIDDEN_PATH_TOKENS):
                continue
            depth = len(rel.parts)
            if max_depth and depth > max_depth:
                continue
            if path.is_dir():
                entries.append({
                    "type": "dir",
                    "path": str(path),
                    "rel": str(rel),
                    "depth": depth,
                })
            else:
                try:
                    size = path.stat().st_size
                except Exception:
                    size = -1
                entries.append({
                    "type": "file",
                    "path": str(path),
                    "rel": str(rel),
                    "depth": depth,
                    "size": size,
                })
            if len(entries) >= MAX_TREE_ENTRIES:
                break
    except Exception as e:
        return {"error": f"glob 실행 실패: {e}"}

    return {
        "root": str(base),
        "max_depth": max_depth,
        "glob": pattern,
        "count": len(entries),
        "truncated": len(entries) >= MAX_TREE_ENTRIES,
        "entries": entries,
    }


def _read_file(path: str, start_line: int, end_line: int) -> dict:
    target = _resolve_safe(path)
    if target is None or not target.exists():
        return {"error": f"path '{path}' 가 SOURCE_ROOTS 안에 없거나 존재하지 않음"}
    if not target.is_file():
        return {"error": f"{target} 는 파일이 아님"}
    try:
        size = target.stat().st_size
    except Exception:
        size = -1
    if size > MAX_FILE_BYTES and (end_line == 0 or end_line - start_line > 1000):
        return {
            "error": (
                f"파일 크기 {size} > {MAX_FILE_BYTES}. start_line/end_line 으로 부분 읽기 필요"
            ),
            "size": size,
        }
    try:
        with target.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return {"error": f"read 실패: {e}"}
    total = len(lines)
    s = max(1, int(start_line) if start_line else 1)
    e = total if not end_line or end_line < 0 else min(total, int(end_line))
    chunk = lines[s - 1 : e]
    return {
        "path": str(target),
        "size": size,
        "total_lines": total,
        "start_line": s,
        "end_line": e,
        "content": "".join(chunk),
    }


def _grep(pattern: str, root_path: str, glob: str, flags: str) -> dict:
    base = _resolve_safe(root_path or str(SOURCE_ROOTS[0]) if SOURCE_ROOTS else "")
    if base is None or not base.exists() or not base.is_dir():
        return {"error": f"root '{root_path}' 잘못됨"}
    if not pattern:
        return {"error": "pattern 필수"}

    re_flags = 0
    if "i" in (flags or ""):
        re_flags |= re.IGNORECASE
    if "m" in (flags or ""):
        re_flags |= re.MULTILINE
    try:
        rx = re.compile(pattern, re_flags)
    except re.error as e:
        return {"error": f"regex compile error: {e}"}

    pat = (glob or "**/*").strip()
    matches: list[dict] = []
    files_seen = 0
    try:
        for path in base.glob(pat):
            if not path.is_file():
                continue
            path_str = str(path).replace("\\", "/")
            if any(tok in path_str for tok in FORBIDDEN_PATH_TOKENS):
                continue
            files_seen += 1
            try:
                size = path.stat().st_size
                if size > MAX_FILE_BYTES * 5:
                    continue
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        if rx.search(line):
                            matches.append({
                                "path": str(path),
                                "lineno": lineno,
                                "line": line.rstrip("\n")[:400],
                            })
                            if len(matches) >= MAX_GREP_MATCHES:
                                break
            except Exception:
                continue
            if len(matches) >= MAX_GREP_MATCHES:
                break
    except Exception as e:
        return {"error": f"grep 실패: {e}"}

    return {
        "root": str(base),
        "pattern": pattern,
        "glob": pat,
        "flags": flags or "",
        "files_searched": files_seen,
        "match_count": len(matches),
        "truncated": len(matches) >= MAX_GREP_MATCHES,
        "matches": matches,
    }


def register(mcp):

    @mcp.tool()
    def list_source_tree(root: str = "", max_depth: int = 4, glob: str = "**/*") -> str:
        """SOURCE_ROOTS 안의 디렉터리 트리를 나열한다.

        white-box 문제의 source 디렉터리 구조 파악용. Planner가 정찰 시작에 호출 권장.

        Args:
            root: 시작 디렉터리 (예: "/sources/codegate2023-fin/general/web-warmup").
                  비우면 SOURCE_ROOTS의 첫 root 사용.
            max_depth: 트리 최대 깊이 (default 4)
            glob: glob 패턴. default "**/*" (모든 항목).
                  예) "**/*.php"  "**/Dockerfile"  "**/README.md"
        """
        return json.dumps(_list_tree(root, int(max_depth) if max_depth else 4, glob),
                          ensure_ascii=False, default=str)

    @mcp.tool()
    def read_source(path: str, start_line: int = 1, end_line: int = 0) -> str:
        """SOURCE_ROOTS 안의 파일을 읽는다 (라인 범위 지정 가능).

        큰 파일은 start_line/end_line 으로 chunk read.

        Args:
            path: 절대 경로 (반드시 SOURCE_ROOTS 안)
            start_line: 시작 라인 (1-based, default 1)
            end_line: 끝 라인 inclusive (0 또는 음수면 EOF까지)
        """
        return json.dumps(
            _read_file(path, int(start_line) if start_line else 1, int(end_line) if end_line else 0),
            ensure_ascii=False, default=str,
        )

    @mcp.tool()
    def grep_source(pattern: str, root: str = "", glob: str = "**/*", flags: str = "") -> str:
        """SOURCE_ROOTS 안의 파일에서 정규식 검색.

        Args:
            pattern: Python 정규식
            root: 시작 디렉터리 (비우면 SOURCE_ROOTS 첫 root)
            glob: 파일 필터 (예: "**/*.php", "**/*.js")
            flags: 조합 — "i" case-insensitive, "m" multiline
        """
        return json.dumps(_grep(pattern, root, glob, flags), ensure_ascii=False, default=str)
