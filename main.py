from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from pathlib import Path
from functools import wraps
from collections import defaultdict
import os
import secrets
import time
import json

app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = "jung-my-team-demo-secret-key"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RESUME_DIR = BASE_DIR / "resumes"
USERS_FILE = DATA_DIR / "users.json"
CONTACTS_FILE = DATA_DIR / "contacts.json"
LOGIN_ATTEMPTS = defaultdict(list)
CAPTCHA_ATTEMPTS = defaultdict(list)
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 8
CAPTCHA_WINDOW_SECONDS = 180
CAPTCHA_MAX_ATTEMPTS = 16
RESUME_MATCH_ATTEMPTS = defaultdict(list)
RESUME_MATCH_WINDOW_SECONDS = 180
RESUME_MATCH_MAX_ATTEMPTS = 12

RESUME_PROFILES = {
    "resume-energy": {
        "file": "resume-energy.pdf",
        "label": "能源 / 电网运维版简历",
        "fit_for": "适合能源、电网运维、缺陷隐患、安全工器具、流程数字化类岗位",
        "keywords": [
            "电网", "供电", "运维", "巡视", "巡检", "缺陷", "隐患", "安全工器具",
            "pms", "挂图作战", "工单", "设备", "能源", "供电所", "抢修"
        ]
    },
    "resume-park": {
        "file": "resume-park.pdf",
        "label": "园区 / 数字孪生版简历",
        "fit_for": "适合智慧园区、数字孪生、三维可视化、园区运营类岗位",
        "keywords": [
            "园区", "智慧园区", "数字孪生", "三维", "可视化", "商户", "运营中心",
            "工业互联网", "企业服务", "招商", "空间", "地图", "可视化平台"
        ]
    },
    "resume-platform-ai": {
        "file": "resume-platform-ai.pdf",
        "label": "B 端平台 / AI 产品版简历",
        "fit_for": "适合 AI 产品经理、B 端平台、SaaS、流程自动化、数据治理类岗位",
        "keywords": [
            "ai", "人工智能", "大模型", "产品经理", "b端", "saas", "平台", "工作流",
            "自动化", "数据治理", "数据提取", "匹配", "流程", "平台产品", "智能审核"
        ]
    }
}


def ensure_data_files():
    DATA_DIR.mkdir(exist_ok=True)

    if not USERS_FILE.exists():
        default_users = [
            {
                "id": 1,
                "username": "admin",
                "password": "123456",
                "name": "Jung Taylor"
            }
        ]
        USERS_FILE.write_text(
            json.dumps(default_users, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    if not CONTACTS_FILE.exists():
        CONTACTS_FILE.write_text("[]", encoding="utf-8")

    RESUME_DIR.mkdir(exist_ok=True)


def load_json(file_path: Path):
    if not file_path.exists():
        return []
    content = file_path.read_text(encoding="utf-8").strip()
    if not content:
        return []
    return json.loads(content)


def save_json(file_path: Path, data):
    file_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def is_rate_limited(bucket, key, window_seconds, max_attempts):
    now = time.time()
    bucket[key] = [stamp for stamp in bucket[key] if now - stamp < window_seconds]
    if len(bucket[key]) >= max_attempts:
        return True
    bucket[key].append(now)
    return False


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    users = load_json(USERS_FILE)
    return next((user for user in users if user["id"] == user_id), None)


def normalize_text(text):
    return " ".join(str(text).lower().split())


def match_resume_profile(jd_text):
    normalized = normalize_text(jd_text)
    score_map = {}

    for resume_id, profile in RESUME_PROFILES.items():
        score = 0
        matched_keywords = []
        for keyword in profile["keywords"]:
            if keyword.lower() in normalized:
                score += 1
                matched_keywords.append(keyword)
        score_map[resume_id] = {
            "score": score,
            "matched_keywords": matched_keywords[:8]
        }

    best_resume_id = max(score_map, key=lambda item: score_map[item]["score"])
    best_profile = RESUME_PROFILES[best_resume_id]
    best_score = score_map[best_resume_id]["score"]

    if best_score == 0:
        best_resume_id = "resume-platform-ai"
        best_profile = RESUME_PROFILES[best_resume_id]

    return {
        "resume_id": best_resume_id,
        "label": best_profile["label"],
        "fit_for": best_profile["fit_for"],
        "matched_keywords": score_map[best_resume_id]["matched_keywords"]
    }


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify({
                    "success": False,
                    "message": "未登录或登录已失效"
                }), 401
            return redirect(url_for("login_page"))
        return view_func(*args, **kwargs)

    return wrapped


ensure_data_files()


@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/login")
def login_page():
    if current_user():
        return redirect(url_for("admin_page"))
    return send_from_directory(BASE_DIR, "login.html")


@app.route("/login.html")
def login_page_html():
    return redirect(url_for("login_page"))


@app.route("/admin")
@login_required
def admin_page():
    return send_from_directory(BASE_DIR, "admin.html")


@app.route("/admin.html")
def admin_page_html():
    return redirect(url_for("admin_page"))


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"success": True, "message": "backend is running"})


@app.route("/api/captcha/challenge", methods=["GET"])
def captcha_challenge():
    track_width = 320
    block_width = 58
    target_left = secrets.randbelow(track_width - block_width - 40) + 20
    challenge = {
        "id": secrets.token_urlsafe(16),
        "target_left": target_left,
        "track_width": track_width,
        "block_width": block_width,
        "tolerance": 6,
        "expires_at": time.time() + 180
    }
    session["captcha_challenge"] = challenge
    session.pop("captcha_ticket", None)
    return jsonify({
        "success": True,
        "challenge": {
            "id": challenge["id"],
            "targetLeft": challenge["target_left"],
            "trackWidth": track_width,
            "blockWidth": block_width
        }
    })


@app.route("/api/captcha/verify", methods=["POST"])
def captcha_verify():
    if is_rate_limited(CAPTCHA_ATTEMPTS, client_ip(), CAPTCHA_WINDOW_SECONDS, CAPTCHA_MAX_ATTEMPTS):
        return jsonify({
            "success": False,
            "message": "验证过于频繁，请稍后再试"
        }), 429

    data = request.get_json(silent=True) or {}
    challenge_id = str(data.get("challengeId", "")).strip()
    slider_left = float(data.get("sliderLeft", -1))
    challenge = session.get("captcha_challenge")

    if not challenge or challenge.get("id") != challenge_id or time.time() > challenge.get("expires_at", 0):
        return jsonify({
            "success": False,
            "message": "验证已失效，请刷新后重试"
        }), 400

    if abs(slider_left - challenge["target_left"]) > challenge["tolerance"]:
        session.pop("captcha_ticket", None)
        return jsonify({
            "success": False,
            "message": "滑动验证未通过，请重试"
        }), 400

    ticket = secrets.token_urlsafe(24)
    session["captcha_ticket"] = {
        "value": ticket,
        "expires_at": time.time() + 120
    }
    return jsonify({
        "success": True,
        "message": "验证通过",
        "captchaTicket": ticket
    })


@app.route("/api/login", methods=["POST"])
def login():
    if is_rate_limited(LOGIN_ATTEMPTS, client_ip(), LOGIN_WINDOW_SECONDS, LOGIN_MAX_ATTEMPTS):
        return jsonify({
            "success": False,
            "message": "登录尝试次数过多，请稍后再试"
        }), 429

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    captcha_ticket = str(data.get("captchaTicket", "")).strip()

    if not username or not password:
        return jsonify({
            "success": False,
            "message": "用户名和密码不能为空"
        }), 400

    ticket_data = session.get("captcha_ticket")
    if (
        not captcha_ticket
        or not ticket_data
        or ticket_data.get("value") != captcha_ticket
        or time.time() > ticket_data.get("expires_at", 0)
    ):
        return jsonify({
            "success": False,
            "message": "请先完成有效的滑动验证"
        }), 400

    users = load_json(USERS_FILE)
    user = next(
        (u for u in users if u["username"] == username and u["password"] == password),
        None
    )

    if not user:
        return jsonify({
            "success": False,
            "message": "用户名或密码错误"
        }), 401

    session["user_id"] = user["id"]
    session.pop("captcha_ticket", None)
    session.pop("captcha_challenge", None)

    return jsonify({
        "success": True,
        "message": "登录成功",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "name": user["name"]
        }
    })


@app.route("/api/me", methods=["GET"])
def me():
    user = current_user()
    if not user:
        return jsonify({
            "success": False,
            "message": "未登录"
        }), 401

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "name": user["name"]
        }
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({
        "success": True,
        "message": "已退出登录"
    })


@app.route("/api/contact", methods=["POST"])
def contact():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip()
    message = str(data.get("message", "")).strip()

    if not name or not email or not message:
        return jsonify({
            "success": False,
            "message": "请填写完整信息"
        }), 400

    contacts = load_json(CONTACTS_FILE)
    new_item = {
        "id": len(contacts) + 1,
        "name": name,
        "email": email,
        "message": message
    }
    contacts.append(new_item)
    save_json(CONTACTS_FILE, contacts)

    return jsonify({
        "success": True,
        "message": "提交成功"
    })


@app.route("/api/resume/match", methods=["POST"])
def match_resume():
    if is_rate_limited(RESUME_MATCH_ATTEMPTS, client_ip(), RESUME_MATCH_WINDOW_SECONDS, RESUME_MATCH_MAX_ATTEMPTS):
        return jsonify({
            "success": False,
            "message": "请求过于频繁，请稍后再试"
        }), 429

    data = request.get_json(silent=True) or {}
    jd_text = str(data.get("jdText", "")).strip()

    if len(jd_text) < 20:
        return jsonify({
            "success": False,
            "message": "请至少粘贴一段较完整的岗位 JD"
        }), 400

    matched = match_resume_profile(jd_text)
    token = secrets.token_urlsafe(24)
    session["resume_download_token"] = {
        "token": token,
        "resume_id": matched["resume_id"],
        "expires_at": time.time() + 900
    }

    return jsonify({
        "success": True,
        "match": {
            "label": matched["label"],
            "fitFor": matched["fit_for"],
            "matchedKeywords": matched["matched_keywords"]
        },
        "downloadUrl": f"/api/resume/download/{token}"
    })


@app.route("/api/resume/download/<token>", methods=["GET"])
def download_resume(token):
    token_data = session.get("resume_download_token")
    if (
        not token_data
        or token_data.get("token") != token
        or time.time() > token_data.get("expires_at", 0)
    ):
        return jsonify({
            "success": False,
            "message": "下载链接已失效，请重新匹配岗位 JD"
        }), 400

    resume_id = token_data["resume_id"]
    profile = RESUME_PROFILES.get(resume_id)
    if not profile:
        return jsonify({
            "success": False,
            "message": "未找到匹配简历"
        }), 404

    session.pop("resume_download_token", None)
    return send_from_directory(
        RESUME_DIR,
        profile["file"],
        as_attachment=True,
        download_name=f"赵培成-{profile['label']}.pdf"
    )


@app.route("/api/contacts", methods=["GET"])
@login_required
def get_contacts():
    contacts = load_json(CONTACTS_FILE)
    return jsonify({
        "success": True,
        "data": contacts
    })


if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000"))
    )
