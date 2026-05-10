# secrets/ — 모든 secret 한 폴더

## 어디에 뭐 넣나

| 파일 | 내용 | 사용처 |
|---|---|---|
| `gcp-key.json` | GCP service account JSON (전체 파일) | GCS upload (KB sync, evidence) |
| `voyage.key` | Voyage AI API key (한 줄) | RAG 임베딩 (`retrieve_similar_patterns`) |
| (옵션) `.env` 같은 string secret 모음 | 미래 추가 secret | — |

## 자동 감지

backend가 시작할 때 `command` entrypoint가:
- `/run/secrets/gcp-key.json` 존재 → `GOOGLE_APPLICATION_CREDENTIALS` 자동 set
- `/run/secrets/voyage.key` 존재 + `VOYAGE_API_KEY` 환경변수 비어있음 → 파일 한 줄을 `VOYAGE_API_KEY` 로 export

`.env` 에서 `VOYAGE_API_KEY=...` override 시 그 값이 우선. file은 fallback.

## .gitignore

`secrets/*` 모두 차단. `secrets/.gitkeep` 와 `secrets/README.md` 만 git에 들어감.

## 협업자가 받는 방법

1. `secrets/` 디렉터리만 git에서 받음 (이 README + .gitkeep)
2. 협업자가 자기 secret 박음:
   ```
   secrets/gcp-key.json   ← GCP Console에서 service account key 다운로드
   secrets/voyage.key     ← https://dash.voyageai.com 에서 API key (한 줄)
   ```
3. `docker compose up -d --build`
4. 끝. 환경변수 자동 set.
