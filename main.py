from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from pathlib import Path
from functools import wraps
from collections import defaultdict
from datetime import datetime
from math import sin, cos
import os
import secrets
import time
import json

app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = "jung-my-team-demo-secret-key"
IS_PRODUCTION = os.getenv("RENDER") == "true" or os.getenv("ENV") == "production"
ALLOWED_ORIGINS = {
    "https://my-xbbu.onrender.com",
    "http://127.0.0.1:5000",
    "http://localhost:5000",
    "null"
}
app.config["SESSION_COOKIE_SAMESITE"] = "None" if IS_PRODUCTION else "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RESUME_DIR = BASE_DIR / "resumes"
USERS_FILE = DATA_DIR / "users.json"
CONTACTS_FILE = DATA_DIR / "contacts.json"
VISITS_FILE = DATA_DIR / "visits.json"
LOGIN_ATTEMPTS = defaultdict(list)
CAPTCHA_ATTEMPTS = defaultdict(list)
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 8
CAPTCHA_WINDOW_SECONDS = 180
CAPTCHA_MAX_ATTEMPTS = 16
RESUME_MATCH_ATTEMPTS = defaultdict(list)
RESUME_MATCH_WINDOW_SECONDS = 180
RESUME_MATCH_MAX_ATTEMPTS = 12
MAX_VISIT_RECORDS = 500

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

    if not VISITS_FILE.exists():
        VISITS_FILE.write_text("[]", encoding="utf-8")

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


def parse_device_label(user_agent):
    ua = (user_agent or "").lower()
    if not ua:
        return "未知设备"
    if "iphone" in ua or "ipad" in ua or "android" in ua or "mobile" in ua:
        return "移动端"
    if "macintosh" in ua or "windows" in ua or "linux" in ua:
        return "桌面端"
    return "其他设备"


def parse_browser_label(user_agent):
    ua = (user_agent or "").lower()
    if "edg" in ua:
        return "Edge"
    if "chrome" in ua and "edg" not in ua:
        return "Chrome"
    if "safari" in ua and "chrome" not in ua:
        return "Safari"
    if "firefox" in ua:
        return "Firefox"
    if "micromessenger" in ua:
        return "微信"
    return "其他浏览器"


def record_visit(payload):
    visits = load_json(VISITS_FILE)
    now = datetime.now()
    user_agent = request.headers.get("User-Agent", "")
    visit_item = {
        "id": secrets.token_hex(8),
        "path": str(payload.get("path") or request.path or "/").strip() or "/",
        "title": str(payload.get("title") or "").strip(),
        "referrer": str(payload.get("referrer") or request.referrer or "").strip(),
        "ip": client_ip(),
        "device": parse_device_label(user_agent),
        "browser": parse_browser_label(user_agent),
        "userAgent": user_agent[:220],
        "visitedAt": now.strftime("%Y-%m-%d %H:%M:%S"),
        "visitedDate": now.strftime("%Y-%m-%d"),
        "visitorKey": f"{client_ip()}|{parse_browser_label(user_agent)}|{parse_device_label(user_agent)}"
    }
    visits.append(visit_item)
    if len(visits) > MAX_VISIT_RECORDS:
        visits = visits[-MAX_VISIT_RECORDS:]
    save_json(VISITS_FILE, visits)


def build_visit_summary():
    visits = load_json(VISITS_FILE)
    visits = sorted(visits, key=lambda item: item.get("visitedAt", ""), reverse=True)
    today = datetime.now().strftime("%Y-%m-%d")
    today_visits = [item for item in visits if item.get("visitedDate") == today]
    unique_visitors = len({item.get("visitorKey", item.get("ip", "")) for item in visits})
    mobile_visits = len([item for item in visits if item.get("device") == "移动端"])

    return {
        "summary": {
            "totalVisits": len(visits),
            "todayVisits": len(today_visits),
            "uniqueVisitors": unique_visitors,
            "mobileVisits": mobile_visits
        },
        "recent": [
            {
                "visitedAt": item.get("visitedAt", ""),
                "path": item.get("path", "/"),
                "title": item.get("title", "") or "首页访问",
                "device": item.get("device", "未知设备"),
                "browser": item.get("browser", "其他浏览器"),
                "ip": item.get("ip", ""),
                "referrer": item.get("referrer", "") or "直接访问"
            }
            for item in visits[:12]
        ]
    }


def build_bigscreen_snapshot():
    visits = load_json(VISITS_FILE)
    contacts = load_json(CONTACTS_FILE)
    now = datetime.now()
    minute_seed = int(time.time() // 60)
    pulse = (sin(time.time() / 12) + 1) / 2
    total_visits = len(visits)
    total_contacts = len(contacts)

    base_installations = 128 + total_visits
    online_nodes = 34 + (minute_seed % 5)
    ai_tasks = 1480 + total_visits * 3 + (minute_seed % 37)
    ai_pass_rate = round(96.2 + pulse * 2.1, 1)
    extraction_rate = round(89.5 + pulse * 4.6, 1)
    avg_latency = round(1.8 + (1 - pulse) * 0.9, 2)

    regions = [
        {"name": "北京", "value": 98 + (minute_seed % 9), "coord": [116.40, 39.90, 22]},
        {"name": "上海", "value": 126 + (minute_seed % 11), "coord": [121.47, 31.23, 28]},
        {"name": "广东", "value": 176 + (minute_seed % 13), "coord": [113.27, 23.13, 34]},
        {"name": "江苏", "value": 142 + (minute_seed % 10), "coord": [118.78, 32.04, 30]},
        {"name": "浙江", "value": 138 + (minute_seed % 8), "coord": [120.15, 30.28, 29]},
        {"name": "四川", "value": 109 + (minute_seed % 7), "coord": [104.07, 30.67, 23]},
        {"name": "湖北", "value": 118 + (minute_seed % 6), "coord": [114.30, 30.59, 25]},
        {"name": "山东", "value": 131 + (minute_seed % 10), "coord": [117.00, 36.67, 26]},
        {"name": "福建", "value": 93 + (minute_seed % 6), "coord": [119.30, 26.08, 19]},
        {"name": "陕西", "value": 84 + (minute_seed % 5), "coord": [108.95, 34.27, 17]}
    ]

    trends = [
        62 + int(8 * sin((minute_seed - 5 + idx) / 2.8)) + idx * 2
        for idx in range(6)
    ]
    ai_trends = [
        71 + int(9 * cos((minute_seed - 5 + idx) / 2.5)) + idx * 3
        for idx in range(6)
    ]

    return {
        "updatedAt": now.strftime("%Y-%m-%d %H:%M:%S"),
        "overview": {
            "openClawInstallations": base_installations,
            "openClawOnlineNodes": online_nodes,
            "aiDailyTasks": ai_tasks,
            "aiPassRate": ai_pass_rate,
            "extractionRate": extraction_rate,
            "avgLatency": avg_latency,
            "websiteVisits": total_visits,
            "hrLeads": total_contacts
        },
        "alerts": [
            f"OpenClaw 在线节点 {online_nodes}/42，当前同步稳定。",
            f"AI 审核通过率 {ai_pass_rate}% ，近 10 分钟无异常峰值。",
            f"字段提取准确率 {extraction_rate}% ，平均延迟 {avg_latency}s。",
            f"网站累计访问 {total_visits} 次，线索留资 {total_contacts} 条。"
        ],
        "regionHeat": regions,
        "installTrend": trends,
        "aiTrend": ai_trends,
        "aiModules": [
            {"name": "图像审核", "value": round(78 + pulse * 18, 1)},
            {"name": "字段提取", "value": round(72 + pulse * 20, 1)},
            {"name": "智能匹配", "value": round(69 + pulse * 16, 1)},
            {"name": "工作流生成", "value": round(64 + pulse * 18, 1)}
        ]
    }


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


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


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


@app.route("/bigscreen")
@login_required
def bigscreen_page():
    return send_from_directory(BASE_DIR, "bigscreen.html")


@app.route("/bigscreen.html")
def bigscreen_page_html():
    return redirect(url_for("bigscreen_page"))


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


@app.route("/api/visit", methods=["POST"])
def track_visit():
    data = request.get_json(silent=True) or {}
    path = str(data.get("path", "")).strip()
    if not path:
        return jsonify({
            "success": False,
            "message": "缺少访问路径"
        }), 400

    record_visit(data)
    return jsonify({
        "success": True
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


@app.route("/api/visits", methods=["GET"])
@login_required
def get_visits():
    stats = build_visit_summary()
    return jsonify({
        "success": True,
        "data": stats
    })


@app.route("/api/bigscreen/realtime", methods=["GET"])
@login_required
def get_bigscreen_realtime():
    return jsonify({
        "success": True,
        "data": build_bigscreen_snapshot()
    })


if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000"))
    )
