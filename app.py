"""
JWT Authorize Token API
GET /jwt?uid=<UID>&password=<PASSWORD>
Response: playername, open_id, player_uid, credit=yasirxt, accesstoken, token
"""

import os
import sys
import json
import time
import asyncio
import httpx
import random
import base64
import traceback
from datetime import datetime
from typing import Optional, Dict, Any

from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Crypto / Protobuf ────────────────────────────────────────
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from google_play_scraper import app as play_scraper

# আপনার existing ফাইল (একই ফোল্ডারে রাখুন)
import YasirXT_pb2

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

CREDIT_TAG = "yasirxt"

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 5000))


# ══════════════════════════════════════════════════════════════
# HTTP client (per-loop safe)
# ══════════════════════════════════════════════════════════════
def make_http_client() -> httpx.AsyncClient:
    """প্রতিটি authorize() কলে নতুন client — Vercel/loop-bind সমস্যা এড়ায়।"""
    return httpx.AsyncClient(
        verify=False,
        timeout=httpx.Timeout(10.0, connect=5.0),
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )


# ══════════════════════════════════════════════════════════════
# AES ENCRYPT
# ══════════════════════════════════════════════════════════════
async def aes_encrypt(payload: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))


# ══════════════════════════════════════════════════════════════
# PROTOBUF HELPERS
# ══════════════════════════════════════════════════════════════
async def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {"wire_type": result.wire_type}
        if result.wire_type == "varint":
            field_data["data"] = result.data
        elif result.wire_type == "string":
            field_data["data"] = result.data
        elif result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = await parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict


async def _generic_proto_dict(content: bytes) -> dict:
    for offset in (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 24, 32, 48, 64, 80, 96, 128):
        if offset >= len(content):
            break
        try:
            parsed = Parser().parse(content[offset:].hex())
            d = await parse_results(parsed)
            if d:
                return d
        except Exception:
            continue
    return {}


def get_proto_field(d, key, default=None):
    if not d or not isinstance(d, dict):
        return default
    if key in d:
        val = d[key].get("data")
        return val if val is not None else default
    if str(key) in d:
        val = d[str(key)].get("data")
        return val if val is not None else default
    return default


async def EncodeVarint(number: int) -> bytes:
    if number < 0:
        raise ValueError("Number must be non-negative")
    out = []
    while True:
        b = number & 0x7F
        number >>= 7
        if number:
            b |= 0x80
        out.append(b)
        if not number:
            break
    return bytes(out)


async def create_varint_field(field_number: int, value: int) -> bytes:
    header = (field_number << 3) | 0
    return await EncodeVarint(header) + await EncodeVarint(value)


async def create_length_delimited_field(field_number: int, value) -> bytes:
    header = (field_number << 3) | 2
    encoded = value.encode() if isinstance(value, str) else value
    return await EncodeVarint(header) + await EncodeVarint(len(encoded)) + encoded


async def create_proto_packet(fields: Dict[int, Any]) -> bytes:
    packet = bytearray()
    for field_number, value in fields.items():
        if isinstance(value, dict):
            nested = await create_proto_packet(value)
            packet.extend(await create_length_delimited_field(field_number, nested))
        elif isinstance(value, int):
            packet.extend(await create_varint_field(field_number, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(await create_length_delimited_field(field_number, value))
    return bytes(packet)


# ══════════════════════════════════════════════════════════════
# STEP 1: GET ACCESS TOKEN (Garena Guest)
# ══════════════════════════════════════════════════════════════
async def get_access_token(client: httpx.AsyncClient, uid: str, password: str):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    hdrs = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    for attempt in range(3):
        try:
            await asyncio.sleep(random.uniform(0.2, 0.4))
            r = await client.post(url, headers=hdrs, data=data)
            if r.status_code == 200:
                j = r.json()
                open_id = j.get("open_id")
                access_token = j.get("access_token")
                platform = j.get("platform", 4)
                if open_id and access_token:
                    return open_id, access_token, platform
            if r.status_code == 429:
                await asyncio.sleep(random.uniform(1.0, 1.5))
                continue
        except Exception:
            pass
        await asyncio.sleep(random.uniform(0.3, 0.6))
    return None


# ══════════════════════════════════════════════════════════════
# STEP 2: VERSION CONFIG
# ══════════════════════════════════════════════════════════════
async def get_playstore_version() -> Optional[str]:
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            None,
            lambda: play_scraper("com.dts.freefireth", lang="en", country="sg"),
        )
        return result.get("version")
    except Exception:
        return None


async def version_config(client: httpx.AsyncClient):
    app_version = await get_playstore_version()
    if not app_version:
        return None
    api_url = (
        "https://version.ggwhitehawk.com/live/ver.php"
        f"?version={app_version}"
        "&lang=hi&device=android&channel=android"
        "&appstore=googleplay&region=SG"
        "&whitelist_version=1.3.0&whitelist_sp_version=1.0.0"
    )
    try:
        r = await client.get(api_url)
        r.raise_for_status()
        data = r.json()
        server_url = data.get("server_url")
        remote_version = data.get("remote_version")
        latest_release_version = data.get("latest_release_version")
        if not server_url or not remote_version or not latest_release_version:
            return None
        return latest_release_version, remote_version, server_url
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
# STEP 3: BUILD MAJOR LOGIN PAYLOAD
# ══════════════════════════════════════════════════════════════
async def build_majorlogin_payload(open_id, access_token, platform, client_version):
    try:
        fields = {
            3: str(datetime.now())[:-7],
            4: "free fire",
            5: 1 if str(platform) in ["1", "4"] else int(platform),
            7: str(client_version),
            8: "Android OS 12 / API-31 (SP1A.210812.016/M025FXXS8CXH1)",
            9: "Handheld",
            11: "WIFI",
            12: 1600,
            13: 720,
            14: "280",
            15: "ARMv7 VFPv3 NEON | 1804 | 8",
            16: 3568,
            17: "Adreno (TM) 506",
            18: "OpenGL ES 3.2 V@0502.0 (GIT@5441528417, Id595308a47, 1648575532) (Date:03/29/22)",
            19: "Google|ff911c33-29e3-485f-922d-c6d633af5dc8",
            20: "172.68.91.178",
            21: "en",
            22: str(open_id),
            23: str(platform),
            24: "Handheld",
            25: {"6": 1, "8": random.randint(100000, 999999)},
            26: "BD",
            29: str(access_token),
            30: 1,
            42: "WIFI",
            57: "7428b253defc164018c604a1ebbfebdf",
            60: 53218,
            61: 7153,
            62: 2993,
            63: 18,
            64: 7281,
            65: 53218,
            66: 7281,
            67: 53218,
            70: 1,
            73: 1,
            74: "/data/app/~~mDd3EgZizFacrcWM7AVCDQ==/com.dts.freefireth-kxbpg2ZYeo4ckFSuUuJlFQ==/lib/arm",
            76: 1,
            77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~mDd3EgZizFacrcWM7AVCDQ==/com.dts.freefireth-kxbpg2ZYeo4ckFSuUuJlFQ==/base.apk",
            78: 3,
            79: 1,
            81: "32",
            83: "2019121229",
            85: 3,
            86: "OpenGLES2",
            87: 3071,
            88: int(platform),
            92: random.randint(10000, 13000),
            93: "android",
            94: "KqsHT2jq/39LltltUCKtrCDmH3iPJabTk1ngEtgg9LExoCMwwbvbV5bCVgCB5zUgNsUTxSrQUnHpxLG31Kiq0LLVbPilOj8Y09POZqzihx9iQMSD",
            95: 111207,
            96: "{\"cur_rate\":null,\"support_etc2\":false}",
            97: 1,
            99: str(platform),
            100: str(platform),
            102: "\u0014\u0006MESX_\u0006f",
            104: 61571,
            105: 1,
            106: "https://dl.bs.freefiremobile.com/live/ABHotUpdates/|https://core-bs.freefiremobile.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
            107: "1.52e738d6c225490e",
        }
        final = await create_proto_packet(fields)
        return await aes_encrypt(final, AES_KEY, AES_IV)
    except Exception:
        traceback.print_exc()
        return None


# ══════════════════════════════════════════════════════════════
# STEP 4: SEND MAJOR LOGIN
# ══════════════════════════════════════════════════════════════
def _extract_jwt_from_bytes(content: bytes) -> Optional[str]:
    if b"eyJ" not in content:
        return None
    start = content.find(b"eyJ")
    end = start
    allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
    while end < len(content) and content[end] in allowed:
        end += 1
    candidate = content[start:end].decode("ascii", errors="ignore")
    if candidate.count(".") >= 2 and len(candidate) > 80:
        return candidate
    return None


def _decode_jwt_payload(jwt_token: str) -> dict:
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return {}
        pad_len = "=" * (-len(parts[1]) % 4)
        raw = base64.urlsafe_b64decode(parts[1] + pad_len)
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _bytes_field(val) -> bytes:
    if val is None:
        return b""
    if isinstance(val, (bytes, bytearray)):
        return bytes(val)
    if isinstance(val, str):
        try:
            if all(c in "0123456789abcdefABCDEF" for c in val) and len(val) % 2 == 0:
                return bytes.fromhex(val)
        except Exception:
            pass
        return val.encode("utf-8", errors="replace")
    return b""


class MajorLoginResult:
    def __init__(self):
        self.token = ""
        self.region = "BD"
        self.account_id = 0
        self.server_time = int(time.time())
        self.aes_ak = b""
        self.iv_i = b""
        self.url = ""
        self.nickname = ""


async def send_majorlogin(client: httpx.AsyncClient, data: bytes, release_version: str, server_url: str):
    try:
        url = f"{server_url.rstrip('/')}/MajorLogin"
        from urllib.parse import urlparse
        netloc = urlparse(server_url).netloc

        req_headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.12f1",
            "X-GA": "v1 1",
            "X-GA-SV": "1789535859",
            "ReleaseVersion": release_version,
            "Host": netloc,
            "Content-Length": str(len(data)),
            "Authorization": "Bearer",
        }

        r = await client.post(url, headers=req_headers, data=data, timeout=10.0)
        content = r.content or b""
        if r.status_code != 200 or len(content) < 20:
            return None

        jwt_token = _extract_jwt_from_bytes(content)
        res_proto = None
        for offset in (0, 4, 8, 16, 32, 64, 80, 96, 128):
            if offset >= len(content):
                break
            try:
                p = YasirXT_pb2.MajorLoginRes()
                p.ParseFromString(content[offset:])
                if (getattr(p, "token", None) or getattr(p, "region", None)
                        or getattr(p, "serverUrl", None)):
                    res_proto = p
                    break
            except Exception:
                continue

        result = MajorLoginResult()
        result.url = server_url

        if res_proto is not None:
            result.token = getattr(res_proto, "token", None) or ""
            result.region = getattr(res_proto, "region", None) or "BD"
            result.account_id = int(getattr(res_proto, "account_id", 0) or 0)
            result.server_time = int(getattr(res_proto, "server_time", 0) or time.time())
            result.aes_ak = _bytes_field(getattr(res_proto, "aes_ak", None))
            result.iv_i = _bytes_field(getattr(res_proto, "iv_i", None))
            su = getattr(res_proto, "url", None)
            if su:
                result.url = su if isinstance(su, str) else str(su)
        else:
            gdict = await _generic_proto_dict(content)
            if gdict:
                tok = jwt_token or get_proto_field(gdict, 8) or get_proto_field(gdict, 1)
                if isinstance(tok, bytes):
                    tok = tok.decode("utf-8", errors="ignore")
                if isinstance(tok, str) and "eyJ" in tok:
                    result.token = tok[tok.find("eyJ"):]
                reg = get_proto_field(gdict, 2)
                if isinstance(reg, str) and 1 < len(reg) <= 8:
                    result.region = reg.upper()
                aid = get_proto_field(gdict, 1)
                if isinstance(aid, int) and aid > 1000:
                    result.account_id = aid

        if not result.token and jwt_token:
            result.token = jwt_token

        if result.token:
            claims = _decode_jwt_payload(result.token)
            if claims:
                for k in ("account_id", "accountId", "uid", "user_id", "sub"):
                    if k in claims and not result.account_id:
                        try:
                            result.account_id = int(claims[k])
                        except Exception:
                            pass
                for k in ("region", "lock_region", "lockRegion", "server_region"):
                    if k in claims and claims[k]:
                        result.region = str(claims[k]).upper()
                for k in ("server_url", "serverUrl", "url", "bp_url"):
                    if k in claims and str(claims[k]).startswith("http"):
                        result.url = str(claims[k])

        if not result.token:
            return None
        if "version" in (result.url or "").lower() or not result.url:
            result.url = server_url
        return result
    except Exception as e:
        print(f"[MajorLogin] Exception: {e}", file=sys.stderr)
        traceback.print_exc()
        return None


# ══════════════════════════════════════════════════════════════
# STEP 5: GET LOGIN DATA (nickname)
# ══════════════════════════════════════════════════════════════
async def send_getlogin(client: httpx.AsyncClient, base_url: str, token: str, release_version: str):
    """
    GetLoginData সাধারণত খালি বডি গ্রহণ করে। এখানে b"" পাঠানো হয়।
    Player UID MajorLoginRes.account_id থেকে নেওয়া হয়।
    """
    try:
        if not base_url:
            return None
        url = f"{base_url.rstrip('/')}/GetLoginData"
        from urllib.parse import urlparse
        netloc = urlparse(base_url).netloc or "clientbp.ppmainecoonghj.com"

        req_headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.12f1",
            "X-GA-SV": "1789535859",
            "X-GA": "v1 1",
            "ReleaseVersion": release_version,
            "Authorization": f"Bearer {token}",
            "Host": netloc,
            "Content-Length": "0",
        }

        r = await client.post(url, headers=req_headers, data=b"", timeout=10.0)
        content = r.content or b""
        if r.status_code != 200 or len(content) < 8:
            return None

        res_proto = YasirXT_pb2.GetLoginDataRes()
        ok = False
        try:
            res_proto.ParseFromString(content)
            if getattr(res_proto, "nickname", None) or getattr(res_proto, "functional_addrs", None):
                ok = True
        except Exception:
            pass

        if not ok:
            for offset in range(0, min(160, len(content))):
                try:
                    c = YasirXT_pb2.GetLoginDataRes()
                    c.ParseFromString(content[offset:])
                    if getattr(c, "nickname", None) or getattr(c, "functional_addrs", None):
                        res_proto = c
                        ok = True
                        break
                except Exception:
                    pass

        nickname = ""
        if ok:
            nickname = getattr(res_proto, "nickname", "") or ""

        if not nickname:
            dict_res = await _generic_proto_dict(content)
            nk = get_proto_field(dict_res, 4, "") or get_proto_field(dict_res, 3, "") or ""
            if isinstance(nk, bytes):
                nk = nk.decode("utf-8", errors="ignore")
            nickname = nk or ""

        return {"nickname": nickname}
    except Exception as e:
        print(f"[GetLoginData] Exception: {e}", file=sys.stderr)
        traceback.print_exc()
        return None


# ══════════════════════════════════════════════════════════════
# MASTER FLOW
# ══════════════════════════════════════════════════════════════
async def authorize(uid: str, password: str) -> Dict[str, Any]:
    client = make_http_client()
    try:
        # 1) access token
        access = await get_access_token(client, uid, password)
        if not access:
            return {"error": "invalid_credentials", "message": "UID/Password login failed"}
        open_id, access_token, platform = access

        # 2) version config
        vc = await version_config(client)
        if not vc:
            return {"error": "version_config_failed", "message": "Could not fetch server_url / version"}
        latest_release_version, remote_version, server_url = vc

        # 3) payload
        payload = await build_majorlogin_payload(open_id, access_token, platform, remote_version)
        if not payload:
            return {"error": "payload_build_failed"}

        # 4) major login
        ml = await send_majorlogin(client, payload, latest_release_version, server_url)
        if not ml or not ml.token:
            return {"error": "major_login_failed", "message": "No JWT token in response"}

        # 5) get login data → nickname
        player_name = ""
        player_uid = ml.account_id or 0
        try:
            gld = await send_getlogin(client, ml.url, ml.token, latest_release_version)
            if gld:
                player_name = gld.get("nickname") or ""
        except Exception:
            pass

        # 6) final
        return {
            "status": "success",
            "credit": CREDIT_TAG,
            "playername": player_name or "",
            "player_uid": player_uid,
            "open_id": open_id,
            "accesstoken": access_token,
            "token": ml.token,
            "region": ml.region,
            "server_url": ml.url,
            "aes_key": ml.aes_ak.hex() if ml.aes_ak else "",
            "aes_iv": ml.iv_i.hex() if ml.iv_i else "",
            "server_time": ml.server_time,
        }
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════
# FLASK APP
# ══════════════════════════════════════════════════════════════
app = Flask(__name__)
CORS(app)


def _run_async(coro):
    """Vercel/serverless-এ নিরাপদে coroutine চালানোর জন্য।"""
    try:
        asyncio.get_running_loop()
        running = True
    except RuntimeError:
        running = False

    if running:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "api": "JWT Authorize Token API",
        "credit": CREDIT_TAG,
        "usage": "/jwt?uid=<UID>&password=<PASSWORD>",
        "example": "/jwt?uid=123456789&password=your_password_here",
        "endpoints": {
            "/jwt": "GET — returns playername, open_id, player_uid, accesstoken, token",
            "/health": "GET — health check",
        },
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": int(time.time())})


@app.route("/jwt", methods=["GET"])
def jwt_api():
    uid = request.args.get("uid", "").strip()
    password = request.args.get("password", "").strip()

    if not uid or not password:
        return jsonify({
            "status": "error",
            "credit": CREDIT_TAG,
            "error": "missing_params",
            "message": "Both uid and password query params are required",
            "example": "/jwt?uid=123456789&password=abcdef123456",
        }), 400

    try:
        result = _run_async(authorize(uid, password))
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "credit": CREDIT_TAG,
            "error": "server_exception",
            "message": str(e),
        }), 500

    if "error" in result and "token" not in result:
        return jsonify({
            "status": "error",
            "credit": CREDIT_TAG,
            **result,
        }), 401

    return jsonify(result)


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"╔══════════════════════════════════════════════╗")
    print(f"║   JWT Authorize Token API  —  {CREDIT_TAG}      ║")
    print(f"╠══════════════════════════════════════════════╣")
    print(f"║   Listening:  http://{HOST}:{PORT}              ")
    print(f"║   Usage:      /jwt?uid=<UID>&password=<PASS>")
    print(f"║   Example:    /jwt?uid=1234&password=abcd   ")
    print(f"╚══════════════════════════════════════════════╝")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)