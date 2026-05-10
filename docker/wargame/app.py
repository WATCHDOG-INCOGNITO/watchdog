"""
Watchdog 검증용 워게임 — 의도적으로 취약한 Flask 앱.
SQLi, Reflected XSS, IDOR, SSRF, LFI 취약점을 포함한다.
절대 인터넷에 노출하지 말 것.
"""

import os
import sqlite3
import urllib.request

from flask import Flask, request, g, render_template_string

app = Flask(__name__)
DB_PATH = "/tmp/wargame.db"

# ------------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, token TEXT)")
    sample_users = [
        (1, "admin",   "admin@wargame.local",   "admin"),
        (2, "alice",   "alice@wargame.local",   "user"),
        (3, "bob",     "bob@wargame.local",     "user"),
    ]
    sample_posts = [
        (1, 1, "Welcome",       "Hello from admin"),
        (2, 2, "Alice's post",  "Some content here"),
        (3, 3, "Bob's diary",   "Private stuff <script>alert(1)</script>"),
    ]
    sample_secrets = [
        (1, "FLAG{sql_injection_works}"),
        (2, "FLAG{you_should_not_see_this}"),
    ]
    for row in sample_users:
        c.execute("INSERT OR IGNORE INTO users VALUES (?,?,?,?)", row)
    for row in sample_posts:
        c.execute("INSERT OR IGNORE INTO posts VALUES (?,?,?,?)", row)
    for row in sample_secrets:
        c.execute("INSERT OR IGNORE INTO secrets VALUES (?,?)", row)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------
# Index — 크롤러가 모든 페이지를 발견할 수 있도록 링크 제공
# ------------------------------------------------------------------

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head><title>Wargame</title></head>
<body>
<h1>Watchdog Wargame</h1>
<ul>
  <li><a href="/search?q=test">Search (XSS)</a></li>
  <li><a href="/user?id=1">User Profile (SQLi)</a></li>
  <li><a href="/profile?uid=1">My Profile (IDOR)</a></li>
  <li><a href="/posts?user_id=1">User Posts</a></li>
  <li><a href="/fetch?url=http://example.com">Fetch URL (SSRF)</a></li>
  <li><a href="/read?file=readme.txt">Read File (LFI)</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/admin">Admin Panel</a></li>
  <li><a href="/redirect?next=/">Redirect</a></li>
</ul>
</body>
</html>
"""


@app.route("/")
def index():
    return INDEX_HTML


# ------------------------------------------------------------------
# 1. SQL Injection — id 파라미터를 쿼리에 직접 삽입
# ------------------------------------------------------------------

@app.route("/user")
def user_profile():
    uid = request.args.get("id", "1")
    db = get_db()
    # 취약: 문자열 포맷팅으로 SQL 직접 삽입
    query = f"SELECT * FROM users WHERE id = {uid}"
    try:
        rows = db.execute(query).fetchall()
        result = [dict(r) for r in rows]
    except Exception as e:
        result = {"error": str(e)}
    return render_template_string("""
    <h2>User Profile</h2>
    <p>Query: {{ query }}</p>
    <pre>{{ result }}</pre>
    <a href="/">Back</a>
    """, query=query, result=result)


# ------------------------------------------------------------------
# 2. Reflected XSS — q 파라미터를 HTML에 그대로 출력
# ------------------------------------------------------------------

@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute("SELECT * FROM posts WHERE title LIKE ?", (f"%{q}%",)).fetchall()
    posts = [dict(r) for r in rows]
    # 취약: q를 이스케이프 없이 HTML에 삽입
    return f"""
    <h2>Search Results</h2>
    <p>Results for: {q}</p>
    <form action="/search" method="GET">
        <input name="q" value="{q}" />
        <button type="submit">Search</button>
    </form>
    <ul>{"".join(f"<li>{p['title']}: {p['body']}</li>" for p in posts)}</ul>
    <a href="/">Back</a>
    """


# ------------------------------------------------------------------
# 3. IDOR — uid 파라미터로 다른 사용자 정보 접근 가능
# ------------------------------------------------------------------

@app.route("/profile")
def profile():
    uid = request.args.get("uid", "1")
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        return "<p>User not found</p>", 404
    user = dict(row)
    return render_template_string("""
    <h2>Profile</h2>
    <p>Username: {{ user.username }}</p>
    <p>Email: {{ user.email }}</p>
    <p>Role: {{ user.role }}</p>
    <a href="/">Back</a>
    """, user=user)


# ------------------------------------------------------------------
# 4. SSRF — url 파라미터의 주소를 서버에서 직접 요청
# ------------------------------------------------------------------

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    if not url:
        return "<p>url parameter required</p>", 400
    try:
        # 취약: 사용자 입력 URL을 서버에서 그대로 요청
        resp = urllib.request.urlopen(url, timeout=5)
        content = resp.read(4096).decode("utf-8", errors="replace")
    except Exception as e:
        content = f"Error: {e}"
    return render_template_string("""
    <h2>Fetch Result</h2>
    <p>URL: {{ url }}</p>
    <pre>{{ content }}</pre>
    <a href="/">Back</a>
    """, url=url, content=content)


# ------------------------------------------------------------------
# 5. LFI (Local File Inclusion) — file 파라미터로 서버 파일 읽기
# ------------------------------------------------------------------

@app.route("/read")
def read_file():
    filename = request.args.get("file", "readme.txt")
    # 취약: 경로 검증 없이 파일 읽기
    try:
        filepath = os.path.join("/app/files", filename)
        with open(filepath, "r") as f:
            content = f.read()
    except Exception as e:
        content = f"Error: {e}"
    return render_template_string("""
    <h2>File Reader</h2>
    <p>File: {{ filename }}</p>
    <pre>{{ content }}</pre>
    <a href="/">Back</a>
    """, filename=filename, content=content)


# ------------------------------------------------------------------
# 추가 페이지 — 크롤러 탐색 범위 확장용
# ------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # 취약: SQL Injection in login
        query = f"SELECT * FROM users WHERE username = '{username}' AND role = '{password}'"
        try:
            row = db.execute(query).fetchone()
            msg = f"Welcome {dict(row)['username']}!" if row else "Invalid credentials"
        except Exception as e:
            msg = f"Error: {e}"
    return f"""
    <h2>Login</h2>
    <p>{msg}</p>
    <form method="POST" action="/login">
        <input name="username" placeholder="username" />
        <input name="password" type="password" placeholder="password" />
        <button type="submit">Login</button>
    </form>
    <a href="/">Back</a>
    """


@app.route("/posts")
def user_posts():
    user_id = request.args.get("user_id", "1")
    db = get_db()
    query = f"SELECT * FROM posts WHERE user_id = {user_id}"
    try:
        rows = db.execute(query).fetchall()
        posts = [dict(r) for r in rows]
    except Exception as e:
        posts = [{"error": str(e)}]
    return render_template_string("""
    <h2>Posts</h2>
    <ul>
    {% for p in posts %}
        <li>{{ p.get('title', '') }}: {{ p.get('body', '') }}</li>
    {% endfor %}
    </ul>
    <a href="/">Back</a>
    """, posts=posts)


@app.route("/admin")
def admin():
    return """
    <h2>Admin Panel</h2>
    <p>Admin area — no auth check (IDOR)</p>
    <ul>
        <li><a href="/admin/users">Manage Users</a></li>
        <li><a href="/admin/export?format=csv">Export Data</a></li>
    </ul>
    <a href="/">Back</a>
    """


@app.route("/admin/users")
def admin_users():
    db = get_db()
    rows = db.execute("SELECT * FROM users").fetchall()
    users = [dict(r) for r in rows]
    return render_template_string("""
    <h2>All Users</h2>
    <table border="1">
    <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
    {% for u in users %}
    <tr><td>{{u.id}}</td><td>{{u.username}}</td><td>{{u.email}}</td><td>{{u.role}}</td></tr>
    {% endfor %}
    </table>
    <a href="/admin">Back</a>
    """, users=users)


@app.route("/admin/export")
def admin_export():
    fmt = request.args.get("format", "json")
    return f"<p>Export format: {fmt}</p><a href='/admin'>Back</a>"


@app.route("/redirect")
def do_redirect():
    target = request.args.get("next", "/")
    return f'<meta http-equiv="refresh" content="0;url={target}"><p>Redirecting to {target}...</p>'


@app.route("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
