# app.py
# -----------------------------
# 一个最小可用的微信对话开放平台回调后端（Flask）
# 特点：
# - /wechat/callback：POST 回调，按平台要求返回 {"text": "..."}。
# - 可选签名校验（设置 WEBHOOK_SECRET 后启用，示例为 HMAC-SHA256(body, secret)）。
# - 可选接入 OpenAI（设置 OPENAI_API_KEY 后启用，否则回显）。
# - / 和 /healthz：便于平台或运维做探活。
# -----------------------------

import os
import json
import hmac
import time
import hashlib
import logging
from typing import Any, Dict
import requests
from flask import Flask, request, jsonify

# ====== 配置区（环境变量为主）======
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()   # 若不设置，则不做签名校验
MAX_REPLY_LEN  = int(os.getenv("MAX_REPLY_LEN", "1500"))   # 防止过长触发风控
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))  # OpenAI 超时秒数

# ====== 日志 ======
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger("wechat-bot")

app = Flask(__name__)

# ====== 工具函数 ======
def verify_signature(raw_body: bytes, headers: Dict[str, str]) -> bool:
    """
    签名校验（可选）：
    - 假设平台在请求头传 'X-Signature'，值为 hex(HMAC_SHA256(body, WEBHOOK_SECRET))
    - 如与你后台的字段/算法不同，请按实际文档修改。
    """
    if not WEBHOOK_SECRET:
        return True  # 未设置密钥时跳过签名校验（开发联调期）
    recv_sig = headers.get("X-Signature", "")
    if not recv_sig:
        return False
    mac = hmac.new(WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, recv_sig)

def extract_user_query(payload: Dict[str, Any]) -> str:
    """
    兼容常见字段命名，避免平台或教程版本差异导致“取不到文本”
    需要时可对照你平台的“请求示例”做精准映射
    """
    candidates = [
        payload.get("query"),
        payload.get("text"),
        payload.get("content"),
        (payload.get("message") or {}).get("text"),
        (payload.get("nlpResult") or {}).get("text"),
    ]
    for c in candidates:
        if isinstance(c, str) and c.strip():
            return c.strip()
    # 都没有：直接返回整个 payload（便于在测试面板观察）
    return json.dumps(payload, ensure_ascii=False)

def ask_openai(prompt: str) -> str:
    if not OPENAI_API_KEY:
        # 未配置 OPENAI_API_KEY：直接回显
        return f"你说的是：{prompt}"
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        data = {
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": "你是微信里的智能助手，请用简洁中文回答。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
        }
        r = requests.post(url, headers=headers, json=data, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        resp = r.json()
        ans = (
            resp.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
        )
        return ans or "（无回复）"
    except Exception as e:
        log.exception("OpenAI 调用失败")
        return f"调用大模型失败：{e}"

# ====== 路由 ======
@app.route("/", methods=["GET"])
def index():
    return "OK - wechat-bot backend", 200

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok", "time": int(time.time())})

@app.route("/wechat/callback", methods=["POST"])
def wechat_callback():
    raw = request.get_data(cache=False)  # 原始字节用于签名
    if not verify_signature(raw, request.headers):
        return jsonify({"code": 401, "msg": "invalid signature"}), 401

    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    log.info("incoming body: %s", body)

    user_query = extract_user_query(body)[:2000]
    if not user_query:
        return jsonify({"text": "（没有拿到输入）"})

    answer = ask_openai(user_query)
    answer = answer[:MAX_REPLY_LEN]  # 长度兜底

    # —— 返回格式：保持最简单且通用 —— #
    # 如平台要求不同字段（如 "answer"/"msg"），按需改这里的 key。
    return jsonify({"text": answer})

# ====== 本地调试入口 ======
if __name__ == "__main__":
    # 本地运行：python app.py
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "3000"))
    app.run(host=host, port=port)
