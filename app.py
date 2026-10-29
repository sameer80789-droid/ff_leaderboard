import json
import time
import uuid
import urllib3
import requests
import threading
import re
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, jsonify, render_template

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONFIGURATION ====================
ACCOUNTS_FILE = "accounts.json"
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

# The exact payload you provided
HEX_PAYLOAD = "52 34 5B 61 84 A6 29 B5 F6 48 63 EF AC 11 DA 55".replace(" ", "")
X_GA_SV = "1793282660"

app = Flask(__name__)

# ==================== PROTOBUF HELPERS ====================
def encode_varint(n: int) -> bytes:
    out = bytearray()
    if n < 0: n &= 0xFFFFFFFFFFFFFFFF
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def _pb_varint(fn, val): return encode_varint((fn << 3) | 0) + encode_varint(val)
def _pb_length(fn, val):
    enc = val.encode('utf-8') if isinstance(val, str) else val
    return encode_varint((fn << 3) | 2) + encode_varint(len(enc)) + enc

def create_proto(fields) -> bytes:
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(field, str): field = int(field)
        if isinstance(value, dict):
            packet.extend(_pb_length(field, bytes(create_proto(value))))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict): packet.extend(_pb_length(field, bytes(create_proto(item))))
                elif isinstance(item, str): packet.extend(_pb_length(field, item))
                elif isinstance(item, (bytes, bytearray)): packet.extend(_pb_length(field, bytes(item)))
                elif isinstance(item, bool): packet.extend(_pb_varint(field, 1 if item else 0))
                elif isinstance(item, int): packet.extend(_pb_varint(field, item))
        elif isinstance(value, bool): packet.extend(_pb_varint(field, 1 if value else 0))
        elif isinstance(value, int): packet.extend(_pb_varint(field, value))
        elif isinstance(value, str): packet.extend(_pb_length(field, value))
        elif isinstance(value, (bytes, bytearray)): packet.extend(_pb_length(field, bytes(value)))
    return bytes(packet)

def encrypt_aes(hex_data: str, key=AES_KEY, iv=AES_IV) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(hex_data), AES.block_size)).hex()

def decode_varint(data, offset):
    result = 0; shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80): return result, offset
        shift += 7
    return None, offset

def decode_protobuf(data):
    result = {}; offset = 0
    while offset < len(data):
        header, offset = decode_varint(data, offset)
        if header is None: break
        fn = header >> 3; wt = header & 0x7
        if wt == 0:
            v, offset = decode_varint(data, offset)
            if v is not None:
                if fn in result:
                    if not isinstance(result[fn], list): result[fn] = [result[fn]]
                    result[fn].append(v)
                else: result[fn] = v
        elif wt == 2:
            length, offset = decode_varint(data, offset)
            if length is None: break
            value = data[offset:offset+length]; offset += length
            try:
                s = value.decode('utf-8')
                parsed = s if s else value.hex()
            except UnicodeDecodeError:
                nested = decode_protobuf(value)
                parsed = nested if nested else value.hex()
            if fn in result:
                if not isinstance(result[fn], list): result[fn] = [result[fn]]
                result[fn].append(parsed)
            else: result[fn] = parsed
        elif wt == 1: offset += 8
        elif wt == 3: offset += 4
        else: break
    return result

# ==================== AUTHENTICATION ====================
def get_version_config(region="PK"):
    url = f"https://version.ggwhitehawk.com/live/ver.php?version=1.132.9&lang=ur&device=android&channel=android&appstore=googleplay&region={region.upper()}&whitelist_version=1.3.0&whitelist_sp_version=1.0.0"
    try:
        r = requests.get(url, verify=False, timeout=10)
        j = r.json()
        return j.get("latest_release_version"), j.get("remote_version"), j.get("server_url"), (j.get("gop_url","").split(";")[0] or "https://ffmconnect.ppmainecoonghj.com"), "1.132.9"
    except: return None

def get_access_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    hdrs = {"Content-Type": "application/x-www-form-urlencoded", "Connection": "close"}
    data = {"uid": str(uid), "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
    try:
        r = requests.post(url, headers=hdrs, data=data, verify=False, timeout=10)
        j = r.json()
        if j.get("open_id") and j.get("access_token"): return j["open_id"], j["access_token"], j.get("platform", 4)
    except: pass
    return None

def get_payload(access_token, open_id, platform, version, region="PK"):
    device_id = f"Google|{uuid.uuid4()}"
    major_login = {
        "3": str(datetime.now())[:-7], "4": "free fire", "5": 1, "7": f"{version}", "8": "Android OS 14 / API-34", "9": "Handheld",
        "11": "CarrierDataNetwork", "12": 1672, "13": 750, "14": "338", "15": "ARMv7 VFPv3 NEON", "16": 3702, "17": "Mali-G52",
        "18": "OpenGL ES 3.2", "19": device_id, "20": "104.28.197.151", "21": "ur", "22": f"{open_id}", "23": f"{platform}", "24": "Handheld", 
        "25": "samsung SM-E135F", "26": region.upper(), "29": f"{access_token}", "30": 1, "42": "Cellular", "57": "7428b253defc164018c604a1ebbfebdf", 
        "60": 52037, "61": 5355, "62": 3723, "63": 3, "64": 5483, "65": 52037, "66": 5483, "67": 52037, "73": 2, 
        "74": "/data/app/~~yACsV8QOk9OexgajWQP30A==/com.dts.freefireth-Bi_wPVrrhYM2nYncc29q7Q==/lib/arm",
        "76": 1, "77": "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~yACsV8QOk9OexgajWQP30A==/com.dts.freefireth-Bi_wPVrrhYM2nYncc29q7Q==/base.apk",
        "78": 3, "79": 1, "81": "32", "83": "2019121229", "86": "OpenGLES2", "87": 8191, "88": int(platform), "92": 16091, "93": "android",
        "94": "KqsHT3Yeqo3RLRl8efNiL3aL/1SHwlSrtK0DwNAqdkNBQz70TeVy+icaIwuR3UK4b65Uf3IG5xBFEv0uu+jQZI+rOYCmNCsXjJT4QcZaYgoaaUGG",
        "95": 111107, "96": "{}", "97": 1, "98": 1, "99": f"{platform}", "100": f"{platform}", "102": "4503454457550c0766", "104": 53792, "105": 1,
        "106": "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/", "107": "c8e41b7a93f02d56e1a94c7b8203f5d1",
    }
    return bytes.fromhex(encrypt_aes(create_proto(major_login).hex()))

def major_login(payload, login_url, release_version):
    url = f"{login_url.rstrip('/')}/MajorLogin"
    req_headers = {
        "Accept": "*/*", "Authorization": "Bearer ", "Content-Type": "application/x-www-form-urlencoded",
        "ReleaseVersion": f"{release_version}", "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1", "X-GA-SV": str(int(time.time())), "X-Unity-Version": "2018.4.12f1",
    }
    try:
        r = requests.post(url, headers=req_headers, data=payload, verify=False, timeout=15)
        if r.status_code != 200: return None
        response_content = r.content
        best = None; best_score = -1
        for offset in [64, 0, 48, 32, 80, 16, 128, 8, 96, 60, 56, 40, 24, 20, 12, 4]:
            if offset >= len(response_content): continue
            cand = decode_protobuf(response_content[offset:])
            if not cand: continue
            has_jwt = ("8" in cand)
            has_url = ("10" in cand)
            score = len(cand) + (100 if has_jwt else 0) + (50 if has_url else 0)
            if score > best_score: best = cand; best_score = score
            if has_jwt and has_url: break
        if not best or "8" not in best: return None
        return {str(k): {"data": v} for k, v in best.items()}
    except: return None

# ==================== LEADERBOARD LOGIC ====================
def clean_name(name):
    """Fixes the Unicode issue by removing invisible Free Fire characters"""
    if not isinstance(name, str): return "Unknown"
    # Removes Hangul fillers and other invisible characters
    cleaned = re.sub(r'[\u3164\u3163\u1160\u115f\u1160\u0000-\u001F\u007F-\u009F]', '', name)
    return cleaned.strip() if cleaned.strip() else "Unknown"

def fetch_and_format_data():
    try:
        with open(ACCOUNTS_FILE, "r") as f:
            acc = json.load(f)[0]
    except: return {"error": "accounts.json not found or invalid"}

    region = acc.get("region", "PK")
    vc = get_version_config(region)
    if not vc: return {"error": "Failed to get version"}
    release_version, client_version, server_url, _, _ = vc

    tg = get_access_token(acc["uid"], acc["password"])
    if not tg: return {"error": "Auth failed"}
    open_id, access_token, platform = tg

    payload = get_payload(access_token, open_id, platform, client_version, region)
    res = major_login(payload, server_url, release_version)
    if not res or "8" not in res: return {"error": "MajorLogin failed"}

    jwt = res["8"]["data"]
    
    # Fetch Leaderboard
    headers = {
        "Host": "clientbp.ppmainecoonghj.com",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": X_GA_SV, "Authorization": f"Bearer {jwt}",
        "X-GA": "v1 1", "ReleaseVersion": release_version,
        "Content-Type": "application/x-www-form-urlencoded", "X-Unity-Version": "2018.4.12f1"
    }
    
    r = requests.post("https://clientbp.ppmainecoonghj.com/Leaderboard", headers=headers, data=bytes.fromhex(HEX_PAYLOAD), verify=False)
    if r.status_code != 200: return {"error": f"LB failed: {r.status_code}"}

    raw_data = decode_protobuf(r.content)
    
    # Format data for the frontend
    formatted_players = []
    if "1" in raw_data and isinstance(raw_data["1"], list):
        for p in raw_data["1"]:
            try:
                uid = p.get("1")
                rank = p.get("4", 0)
                inner = p.get("3", {})
                name = inner.get("1", {}).get("3", "Unknown")
                points = inner.get("4", 0)
                
                formatted_players.append({
                    "rank": rank,
                    "name": clean_name(name),
                    "uid": uid,
                    "points": points
                })
            except: continue

    return {"status": "success", "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "players": formatted_players}

# ==================== WEB SERVER & BACKGROUND TASK ====================
latest_data = {"status": "loading", "players": []}

def background_updater():
    global latest_data
    while True:
        print("[*] Fetching live leaderboard...")
        data = fetch_and_format_data()
        if data.get("status") == "success":
            latest_data = data
            print(f"[+] Updated! Found {len(data['players'])} players.")
        else:
            print(f"[-] Update failed: {data.get('error')}")
        
        # Sleep for 5 minutes (300 seconds)
        time.sleep(300)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/leaderboard")
def api_leaderboard():
    return jsonify(latest_data)

if __name__ == "__main__":
    # Start fetching data in the background immediately
    threading.Thread(target=background_updater, daemon=True).start()
    # Start Flask server
    app.run(host="0.0.0.0", port=8080)