#!/usr/bin/env python3
"""
/raw-sources 에 마운트된 CTF 대회 디렉토리에서
**/prob/for_user 경로만 찾아 /sources 에 동일한 구조로 심볼릭 링크한다.

결과 예시:
  /raw-sources/codegate2024-final/gen/web-cgservice/prob/for_user/
  →  /sources/codegate2024-final/gen/web-cgservice/prob/for_user  (symlink)

에이전트의 SOURCE_ROOTS=/sources 이므로 for_organizer, flag, exploit 등은
파일시스템 레벨에서 아예 존재하지 않는다.
"""
import os
from pathlib import Path

RAW = Path("/raw-sources")
DST = Path("/sources")


def main():
    if not RAW.exists():
        print("[link_for_user] /raw-sources not found — skipping")
        return

    count = 0
    for fu_dir in RAW.rglob("for_user"):
        if not fu_dir.is_dir():
            continue
        rel = fu_dir.relative_to(RAW)
        target = DST / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            target.unlink() if target.is_symlink() else None
        os.symlink(str(fu_dir), str(target))
        count += 1
        print(f"  {rel}")

    print(f"[link_for_user] linked {count} for_user dirs → /sources")


if __name__ == "__main__":
    main()
