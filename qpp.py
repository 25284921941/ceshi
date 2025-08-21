import os, hmac, hashlib, json
from flask import Flask, request, jsonify
import requests

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")  # 平台“自定义服务”里配置的密钥（若有）
MODEL = "gpt-4o-mini"

app = Flask(__name__)

def verify_signature(raw_body: bytes, headers) -> bool:
    """
    占位签名校验逻辑：
    - 假设平台在请求头里放了 'X-Signature'，值为 hex(HMAC_SHA256(body, secret))
    - 实际字段名/算法以“微信对话开放平台”后台说明为准，然后替换这里即可
    """
    if not WEBHOOK_SECRET:
        return True  # 未配置则跳过校验（测试期）
    sig = headers.get("X-Signature", "")
    if not sig:
        return False
    mac = hmac.new(WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    # 常量时间比较，避免时序攻击
    return hmac.compare_digest(mac, sig)

def ask_openai(prompt: str) -> str:
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}",
               "Content-Type": "application/json"}
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "你是微信里的智能助手，请用简洁中文回答。"},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        return (data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                    .strip()) or "（无回复）"
    except Exception as e:
        return f"调用大模型失败：{e}"

def extract_user_query(body: dict) -> str:
    """
    兼容多种可能的字段命名（不同版本/教程里命名略有差异）
    你也可以在平台里自定义转发格式后，按固定字段读取。
    """
    candidates = [
        body.get("query"),
        body.get("text"),
        body.get("content"),
        (body.get("nlpResult") or {}).get("text"),
        (body.get("message") or {}).get("text"),
    ]
    for c in candidates:
        if isinstance(c, str) and c.strip():
            return c.strip()
    # 兜底：直接序列化整个 payload，方便调试
    return json.dumps(body, ensure_ascii=False)

@app.route("/wechat/callback", methods=["POST"])
def wechat_callback():
    raw = request.get_data()  # 原始字节用于签名
    if not verify_signature(raw, request.headers):
        return jsonify({"code": 401, "msg": "invalid signature"}), 401

    try:
        body = request.get_json(force=True, silent=False) or {}
    except Exception:
        return jsonify({"code": 400, "msg": "bad json"}), 400

    user_query = extract_user_query(body)[:2000]  # 防止过长
    if not user_query:
        return jsonify({"code": 400, "msg": "empty query"}), 400

    if not OPENAI_API_KEY:
        answer = "未配置 OPENAI_API_KEY"
    else:
        answer = ask_openai(user_query)
        # 简单限长，避免平台侧风控/卡片超长
        answer = answer[:1500]

    """
    返回格式占位：
    - 很多对话平台接受 { "text": "…"} 或 { "answer": "…" }
    - 你可在“自定义服务/回调”里指定“字段映射/返回模板”，与此对齐即可。
    """
    return jsonify({
        "text": answer,
        # 可选：给平台看的调试回传
        "meta": {
            "echo": user_query,
            "model": MODEL
        }
    })
    
if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"),
            port=int(os.getenv("PORT", "3000")),
            debug=False)
