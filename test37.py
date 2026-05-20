# L2 J6B综合诊断工具 原界面版（修复FDA读不到故障｜端口9034）
from flask import Flask, render_template_string, request, jsonify
import socket
import struct
from datetime import datetime
import time
import threading
import re, json, os, sys
import webbrowser

app = Flask(__name__)

# ====================== 配置 ======================
GW_IP = "169.254.1.0"
UDS_PORT = 13400
SOURCE_ADDR = 0xEF5
TARGET_ADDR_ADM = 0x006F
SERVER_PORT = 9038

DID_MAP = {
    "FDA3": b"\x22\xFD\xA3",
    "FDA0": b"\x22\xFD\xA0",
    "FDA7": b"\x22\xFD\xA7"
}

keep_alive_flag = False

# FDA3故障库
# Reduced static table to a minimal fallback to keep the source small.
# Full DB is loaded from external `data/fda3_fault_db.json` (generated or provided).
_fda3_fault_db_static = {
    (3, 0): {"name": "F120camNotCalib_fault", "desc": "前视cam标定未成功或未标定时"},
    (3, 1): {"name": "F120camSNdiff_fault", "desc": "前视cam序列号比对错误"},
}

# lazy load / external data file support for fda3_fault_db
fda3_fault_db = None
_fda3_fault_db_loaded = False

def _get_data_file_path():
    base = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
    return os.path.join(base, "data", "fda3_fault_db.json")

def load_fda3_fault_db():
    """Load compact FDA3 fault DB from external JSON if present.
    If not present, build a compact file from the static table (only non-empty entries)
    and save it to ./data/fda3_fault_db.json for future runs. This keeps source small
    when packaging with PyInstaller (--onefile) while remaining editable.
    """
    global fda3_fault_db, _fda3_fault_db_loaded
    if _fda3_fault_db_loaded:
        return
    path = _get_data_file_path()
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                j = json.load(f)
            # convert keys "byte,bit" -> tuple
            fda3_fault_db = { tuple(map(int, k.split(","))): v for k, v in j.items() }
            _fda3_fault_db_loaded = True
            return
    except Exception:
        # ignore and fallback to static
        pass

    # build compact map from static table (only keep entries with name or desc)
    compact = {}
    for k, v in _fda3_fault_db_static.items():
        if (v.get("name") or v.get("desc")):
            compact[k] = v

    # try to persist compact JSON for future runs
    try:
        out_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "fda3_fault_db.json")
        # write with keys as "byte,bit" strings
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({f"{a},{b}": val for (a,b), val in compact.items()}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    fda3_fault_db = compact
    _fda3_fault_db_loaded = True

# ====================== DoIP ======================

# ====================== DoIP ======================
def build_routing_activation(source_addr: int) -> bytes:
    header = b"\x02\xFD\x00\x05"
    len_buf = struct.pack(">I", 7)
    payload = struct.pack("!HB4s", source_addr, 0x00, b"\x00\x00\x00")
    return header + len_buf + payload

def build_diag_msg(src, dst, uds_data: bytes) -> bytes:
    header = b"\x02\xFD\x80\x01"
    len_buf = struct.pack(">I", 4 + len(uds_data))
    addr_buf = struct.pack(">HH", src, dst)
    return header + len_buf + addr_buf + uds_data

# ✅ 修复：正确解析8002响应
def extract_uds_data(doip_hex: str) -> str:
    # normalize
    doip_hex = (doip_hex or "").upper()
    pos = doip_hex.find("8002")
    if pos != -1:
        return doip_hex[pos+12:]
    pos = doip_hex.find("8001")
    if pos != -1:
        return doip_hex[pos+12:]
    return doip_hex


def recv_doip_packet(sock, timeout=2) -> str:
    """Receive a single DoIP packet from `sock` and return its hex string (upper).
    Reads 8-byte DoIP header first to obtain payload length, then reads the full payload.
    If anything fails or socket closes early, returns whatever was read as hex.
    """
    try:
        sock.settimeout(timeout)
        header = b""
        # read 8 bytes header (4 bytes protocol + 4 bytes length)
        while len(header) < 8:
            chunk = sock.recv(8 - len(header))
            if not chunk:
                break
            header += chunk
        if len(header) < 8:
            return header.hex().upper()
        length = struct.unpack(">I", header[4:8])[0]
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(min(4096, length - len(payload)))
            if not chunk:
                break
            payload += chunk
        return (header + payload).hex().upper()
    except Exception:
        # fall back to a single recv
        try:
            data = sock.recv(4096)
            return data.hex().upper()
        except Exception:
            return ""

# ====================== 连接 ======================
def check_vehicle_connection():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        res = sock.connect_ex((GW_IP, UDS_PORT))
        sock.close()
        return res == 0
    except:
        return False

# ====================== FDA解析 ======================
def decode_fda3(hex_str):
    try:
        # ensure fault DB is loaded (lazy loading supports external data and PyInstaller)
        load_fda3_fault_db()
        db = fda3_fault_db or {}
        raw_bytes = bytes.fromhex(hex_str.strip())
        fault_list = []
        for byte_idx in range(len(raw_bytes)):
            byte_val = raw_bytes[byte_idx]
            for bit_idx in range(8):
                if (byte_val >> (7 - bit_idx)) & 1:
                    key = (byte_idx, bit_idx)
                    fault_info = db.get(key, {"name":"reserved","desc":"reserved"})
                    fault_list.append({
                        "byte": byte_idx+1,
                        "bit": bit_idx+1,
                        "name": fault_info["name"],
                        "desc": fault_info["desc"]
                    })
        return fault_list
    except:
        return []

# ✅ 修复：FDA3读取（不上1003、完整收包、正确解析62FDA3）
def read_did(did_name):
    try:
        if did_name not in DID_MAP:
            return {"log":"无效DID指令","faults":[]}
        uds_cmd = DID_MAP[did_name]
        log_list = []
        now_time = datetime.now().strftime("%H:%M:%S")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((GW_IP, UDS_PORT))
        log_list.append(f"[{now_time}] TCP连接建立成功")

        # 路由激活
        ra_pkt = build_routing_activation(SOURCE_ADDR)
        sock.sendall(ra_pkt)
        log_list.append(f"[{now_time}] 发送路由: {ra_pkt.hex().upper()}")
        ra_resp = sock.recv(1024)
        log_list.append(f"[{now_time}] 路由响应: {ra_resp.hex().upper()}")

        # 直接发FDA（不上1003）
        diag_pkt = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, uds_cmd)
        sock.sendall(diag_pkt)
        log_list.append(f"[{now_time}] 发送{did_name}: {uds_cmd.hex().upper()}")

        # ✅ 完整收包（解决截断问题）
        recv_hex = recv_doip_packet(sock, timeout=3)
        pure_uds = extract_uds_data(recv_hex)
        log_list.append(f"[{now_time}] 完整响应: {recv_hex}")
        log_list.append(f"[{now_time}] 解析UDS: {pure_uds}")

        fault_result = []
        # ✅ 严格匹配62FDA3
        if "62FDA3" in recv_hex:
            idx = recv_hex.find("62FDA3")
            data_hex = recv_hex[idx+6:]
            fault_result = decode_fda3(data_hex)

        sock.close()
        return {"log":"\n".join(log_list), "faults": fault_result}
    except Exception as e:
        return {"log":f"通信异常: {str(e)}","faults":[]}

# ====================== 屏蔽 ======================
def do_mask_process(step_data):
    try:
        log_list = []
        ret_step = 0
        ret_seed = ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((GW_IP, UDS_PORT))
        log_list.append("建立TCP通信成功")

        ra_pkt = build_routing_activation(SOURCE_ADDR)
        sock.sendall(ra_pkt)
        # consume activation response
        _ = recv_doip_packet(sock, timeout=2)

        if step_data["step"] >= 1:
            pkt1 = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, bytes.fromhex("1003"))
            sock.sendall(pkt1)
            log_list.append(f"发送10 03会话: 1003")
            resp1 = recv_doip_packet(sock, timeout=2)
            log_list.append(f"1003响应: {extract_uds_data(resp1)}")
            ret_step = 1

        if step_data["step"] >= 2:
            pkt2 = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, bytes.fromhex("3E80"))
            sock.sendall(pkt2)
            log_list.append(f"发送3E 80保活: 3E80")
            resp2 = recv_doip_packet(sock, timeout=2)
            log_list.append(f"3E80响应: {extract_uds_data(resp2)}")
            ret_step = 2

        if step_data["step"] >= 3:
            pkt3 = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, bytes.fromhex("2701"))
            sock.sendall(pkt3)
            log_list.append(f"发送27 01请求: 2701")
            resp3 = recv_doip_packet(sock, timeout=2)
            log_list.append(f"2701响应: {extract_uds_data(resp3)}")
            if "6701" in resp3:
                ret_seed = resp3[resp3.find("6701")+4:]
            ret_step = 3

        if step_data["step"] >=4 and step_data.get("key"):
            key_str = step_data.get("key","").strip().upper()
            cmd4 = bytes.fromhex(f"2702{key_str}")
            pkt4 = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, cmd4)
            sock.sendall(pkt4)
            log_list.append(f"发送27 02密钥: {key_str}")
            time.sleep(0.3)
            resp4 = recv_doip_packet(sock, timeout=2)
            log_list.append(f"密钥响应: {extract_uds_data(resp4)}")
            ret_step =4

        if step_data["step"] >=5:
            full_fill = bytes.fromhex("F"*512)
            cmd5 = b"\x2E\xFD\x00" + full_fill
            pkt5 = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, cmd5)
            sock.sendall(pkt5)
            log_list.append(f"发送2E FD 00屏蔽指令")
            time.sleep(1)
            resp5 = recv_doip_packet(sock, timeout=3)
            log_list.append(f"屏蔽00响应: {extract_uds_data(resp5)}")
            ret_step =5

        if step_data["step"] >=6:
            full_fill2 = bytes.fromhex("F"*512)
            cmd6 = b"\x2E\xFD\x01" + full_fill2
            pkt6 = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, cmd6)
            sock.sendall(pkt6)
            log_list.append(f"发送2E FD 01屏蔽指令")
            time.sleep(1)
            resp6 = recv_doip_packet(sock, timeout=3)
            log_list.append(f"屏蔽01响应: {extract_uds_data(resp6)}")
            ret_step =6

        sock.close()
        return {"status":"ok","log":"\n".join(log_list),"step":ret_step,"seed":ret_seed}
    except Exception as e:
        return {"status":"err","log":f"执行失败: {str(e)}","step":0,"seed":""}

# ====================== 自定义 ======================
def keep_alive_loop(sock):
    global keep_alive_flag
    while keep_alive_flag:
        try:
            pkt = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, bytes.fromhex("3E80"))
            sock.sendall(pkt)
            time.sleep(1)
        except:
            break

def send_custom_uds_cmds(cmd_text:str) -> str:
    global keep_alive_flag
    lines = [line.strip().upper() for line in cmd_text.splitlines() if line.strip()]
    if not lines:
        return "未输入任何诊断指令"
    log_buf = []
    now_base = datetime.now().strftime("%H:%M:%S")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(20)
        sock.connect((GW_IP, UDS_PORT))
        log_buf.append(f"[{now_base}] 自定义诊断：建立TCP连接成功")

        ra_pkt = build_routing_activation(SOURCE_ADDR)
        sock.sendall(ra_pkt)
        ra_resp = recv_doip_packet(sock, timeout=2)
        log_buf.append(f"[{now_base}] 路由激活完成，响应：{ra_resp}")

        keep_alive_flag = True
        threading.Thread(target=keep_alive_loop, args=(sock,), daemon=True).start()
        log_buf.append("已开启自动保活：每隔1s自动发送3E 80")

        for idx, hex_cmd in enumerate(lines):
            t_str = datetime.now().strftime("%H:%M:%S")
            try:
                uds_bytes = bytes.fromhex(hex_cmd)
                doip_pkt = build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, uds_bytes)
                sock.sendall(doip_pkt)
                log_buf.append(f"\n[{t_str}] 发送指令：{hex_cmd}")
                resp = recv_doip_packet(sock, timeout=3)
                pure_data = extract_uds_data(resp)
                log_buf.append(f"[{t_str}] 回复有效报文：{pure_data}")
            except Exception as e:
                log_buf.append(f"[{t_str}] 指令{hex_cmd}发送异常：{str(e)}")
            if idx != len(lines)-1:
                time.sleep(3)

        keep_alive_flag = False
        sock.close()
        return "\n".join(log_buf)
    except Exception as e:
        keep_alive_flag = False
        return f"自定义诊断连接失败：{str(e)}"

# ====================== 整车故障读写 ======================
def read_all_dtc() -> str:
    log_list = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((GW_IP, UDS_PORT))
        log_list.append("建立整车诊断连接成功")
        sock.sendall(build_routing_activation(SOURCE_ADDR))
        _ = recv_doip_packet(sock, timeout=2)

        sock.sendall(build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, bytes.fromhex("1001")))
        log_list.append("发送10 01默认会话")
        resp1 = recv_doip_packet(sock, timeout=2)
        log_list.append(f"响应：{extract_uds_data(resp1)}")
        time.sleep(0.2)

        dtc_cmd = bytes.fromhex("1902")
        sock.sendall(build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, dtc_cmd))
        log_list.append("发送19 02 读取当前故障码")
        dtc_resp = recv_doip_packet(sock, timeout=3)
        log_list.append(f"故障码列表：{extract_uds_data(dtc_resp)}")
        sock.close()
        return "\n".join(log_list)
    except Exception as e:
        return f"读取故障失败：{str(e)}"

def clear_all_dtc() -> str:
    log_list = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((GW_IP, UDS_PORT))
        log_list.append("建立整车诊断连接成功")
        sock.sendall(build_routing_activation(SOURCE_ADDR))
        _ = recv_doip_packet(sock, timeout=2)

        sock.sendall(build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, bytes.fromhex("1001")))
        log_list.append("进入默认会话")
        _ = recv_doip_packet(sock, timeout=2)
        time.sleep(0.2)

        clear_cmd = bytes.fromhex("14FFFFFF")
        sock.sendall(build_diag_msg(SOURCE_ADDR, TARGET_ADDR_ADM, clear_cmd))
        log_list.append("发送14 FF FF FF 清除所有故障")
        clear_resp = recv_doip_packet(sock, timeout=3)
        log_list.append(f"清除结果：{extract_uds_data(clear_resp)}")
        sock.close()
        return "\n".join(log_list)
    except Exception as e:
        return f"清除故障失败：{str(e)}"

# ====================== 前端（原界面完全不变）======================
@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>L2 J6B综合诊断工具</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: "Microsoft YaHei", sans-serif;
        }
        html, body {
            height: 100%;
            margin: 0;
            padding: 0;
            background: #dce2ed;
            display: flex;
            flex-direction: column;
        }
        .wrapper {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 40px 20px;
        }
        .container {
            width: 900px;
            background: rgba(255,255,255,0.72);
            border-radius: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            padding: 36px;
            border: 1px solid rgba(255,255,255,0.8);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 28px;
        }
        .title {
            font-size: 26px;
            font-weight: 700;
            color: #1d1d1f;
        }
        .status-pill {
            padding: 8px 14px;
            border-radius: 999px;
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-online {
            background: rgba(52,199,89,0.15);
            color: #097c2c;
        }
        .status-offline {
            background: rgba(255,59,48,0.15);
            color: #c71710;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            animation: pulse 1.6s infinite;
        }
        .status-online .status-dot {
            background: #34c759;
        }
        .status-offline .status-dot {
            background: #ff3b30;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: .4; transform: scale(.9); }
        }
        .segmented {
            display: flex;
            background: rgba(0,0,0,0.05);
            border-radius: 14px;
            padding: 4px;
            position: relative;
            height: 52px;
            margin-bottom: 28px;
            z-index: 1;
        }
        .seg-slider {
            position: absolute;
            top: 4px;
            left: 4px;
            width: calc(25% - 4px);
            height: 44px;
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.12);
            transition: transform 0.35s;
            z-index: 1;
        }
        .seg-item {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 15px;
            font-weight: 600;
            color: #86868b;
            cursor: pointer;
            position: relative;
            z-index: 10;
            transition: 0.2s;
        }
        .seg-item:active {
            transform: scale(0.97);
        }
        .seg-item.active {
            color: #1d1d1f !important;
        }
        .seg-1 .seg-slider { transform: translateX(0); }
        .seg-2 .seg-slider { transform: translateX(100%); }
        .seg-3 .seg-slider { transform: translateX(200%); }
        .seg-4 .seg-slider { transform: translateX(300%); }
        .panel {
            display: none;
            opacity: 0;
            transform: translateY(10px);
            transition: all .35s;
        }
        .panel.active {
            display: block;
            opacity: 1;
            transform: translateY(0);
        }
        .btn-grid {
            display: grid;
            grid-template-columns: repeat(3,1fr);
            gap: 14px;
            margin-bottom: 24px;
        }
        .func-btn {
            height: 58px;
            border: none;
            border-radius: 14px;
            background: #fff;
            font-size: 15px;
            font-weight: 600;
            color: #007bff;
            cursor: pointer;
            transition: 0.2s;
        }
        .func-btn:hover {
            background: #f0f7ff;
        }
        .func-btn:active {
            transform: scale(0.97);
        }
        .step-card {
            background: rgba(255,255,255,0.9);
            border-radius: 16px;
            padding: 18px 20px;
            margin-bottom: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        }
        .step-done {
            background: rgba(52,199,89,0.12);
        }
        .step-title {
            font-size: 15px;
            font-weight: 600;
            color: #1d1d1f;
        }
        .seed-box {
            background: #f2f2f7;
            border-radius: 12px;
            padding: 12px 14px;
            margin-top: 10px;
            font-size: 14px;
        }
        .key-input {
            width: 100%;
            margin-top: 10px;
            padding: 12px 14px;
            border-radius: 12px;
            border: 1px solid #d2d2d7;
            font-size: 14px;
            outline: none;
        }
        .btn-run {
            margin-top: 10px;
            width: 100%;
            height: 44px;
            border-radius: 12px;
            background: #007bff;
            color: #fff;
            border: none;
            cursor: pointer;
            transition: 0.2s;
        }
        .btn-run:active {
            transform: scale(0.97);
        }
        .fault-title {
            font-size: 16px;
            font-weight: 700;
            color: #1d1d1f;
            margin-bottom: 14px;
        }
        .fault-card {
            background: #fff;
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.06);
        }
        .fault-name {
            font-size: 16px;
            font-weight: 700;
            color: #1d1d1f;
            margin-bottom: 4px;
        }
        .fault-desc {
            font-size: 14px;
            color: #86868b;
        }
        .custom-textarea {
            width: 100%;
            height: 220px;
            padding: 16px;
            border-radius: 16px;
            border: 1px solid #d2d2d7;
            background: #f9f9fb;
            outline: none;
            font-size: 13px;
            line-height: 1.8;
            resize: none;
            margin-bottom: 16px;
        }
        .custom-tip {
            font-size: 13px;
            color: #6e6e73;
            margin-bottom: 12px;
            line-height: 1.6;
        }
        .log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 32px;
            margin-bottom: 12px;
        }
        .log-title {
            font-size: 16px;
            font-weight: 700;
            color: #1d1d1f;
        }
        .log-btn {
            width: 36px;
            height: 36px;
            border-radius: 12px;
            background: rgba(0,0,0,0.05);
            border: none;
            cursor: pointer;
            transition: 0.2s;
        }
        .log-btn:hover {
            background: rgba(0,0,0,0.1);
        }
        .log-btn:active {
            transform: scale(0.97);
        }
        .log-box {
            background: #1d1d1f;
            color: #f2f2f7;
            border-radius: 16px;
            padding: 20px;
            min-height: 120px;
            max-height: 420px;
            overflow-y: auto;
            font-family: "Microsoft YaHei", Consolas, sans-serif !important;
            font-size: 12px;
            line-height: 1.6;
            white-space: pre-wrap;
        }
        .loading {
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.2);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 999;
        }
        .loading-box {
            background: rgba(255,255,255,0.9);
            border-radius: 16px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 12px;
        }
        .spinner {
            width: 36px;
            height: 36px;
            border: 3px solid #e1e1e2;
            border-top: 3px solid #007bff;
            border-radius: 50%;
            animation: spin .8s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        footer {
            text-align: center;
            font-size: 12px;
            color: #86868b;
            padding: 12px 20px 20px;
            width: 100%;
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="container">
            <div class="header">
                <div class="title">L2 J6B综合诊断工具</div>
                <div id="status" class="status-pill status-offline">
                    <div class="status-dot"></div><span>加载中</span>
                </div>
            </div>

            <div class="segmented seg-1" id="segMain">
                <div class="seg-slider"></div>
                <div class="seg-item active" onclick="switchTab(0)">ADM故障诊断</div>
                <div class="seg-item" onclick="switchTab(1)">ADM故障屏蔽</div>
                <div class="seg-item" onclick="switchTab(2)">ADM自定义诊断</div>
                <div class="seg-item" onclick="switchTab(3)">整车故障读写</div>
            </div>

            <div class="panel active" id="panel0">
                <div class="btn-grid">
                    <button class="func-btn" onclick="readDID('FDA3')">当前所有故障<br>FDA3</button>
                    <button class="func-btn" onclick="readDID('FDA7')">上报应用层故障<br>FDA7</button>
                    <button class="func-btn" onclick="readDID('FDA0')">DTC与DID故障<br>FDA0</button>
                </div>
            </div>

            <div class="panel" id="panel1">
                <div class="btn-grid">
                    <button class="func-btn" onclick="startMask()">开始执行屏蔽</button>
                </div>
                <div style="margin-top:16px;">
                    <div class="step-card" id="s1"><div class="step-title">步骤1：10 03 会话</div></div>
                    <div class="step-card" id="s2"><div class="step-title">步骤2：3E 80 保活</div></div>
                    <div class="step-card" id="s3">
                        <div class="step-title">步骤3：27 01 获取 Seed</div>
                        <div class="seed-box" id="seedShow"></div>
                    </div>
                    <div class="step-card" id="s4">
                        <div class="step-title">步骤4：27 02 输入 Key</div>
                        <input class="key-input" id="keyInput" placeholder="请输入Key">
                        <button class="btn-run" onclick="sendKey()">确认解锁</button>
                    </div>
                    <div class="step-card" id="s5"><div class="step-title">步骤5：2E FD 00 写入</div></div>
                    <div class="step-card" id="s6"><div class="step-title">步骤6：2E FD 01 写入</div></div>
                </div>
            </div>

            <div class="panel" id="panel2">
                <div class="custom-tip">
                    提示：仅支持对ADM(6F)进行诊断，一行一条UDS指令<br>
                    自动规则：多行间隔3s，全程1s自动3E80保活
                </div>
                <textarea class="custom-textarea" id="customCmdInput" placeholder="1003&#10;3E80&#10;2701&#10;2EFD00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF&#10;2EFD01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"></textarea>
                <div class="btn-grid">
                    <button class="func-btn" onclick="sendCustomCmd()">执行批量诊断</button>
                    <button class="func-btn" onclick="clearCustomInput()">清空</button>
                    <button class="func-btn" onclick="fillDemoCmd()">填入示例</button>
                </div>
            </div>

            <div class="panel" id="panel3">
                <div class="btn-grid">
                    <button class="func-btn" onclick="readVehicleDtc()">读取整车故障</button>
                    <button class="func-btn" onclick="clearVehicleDtc()">清除整车故障</button>
                    <button class="func-btn" onclick="refreshNetStatus()">刷新状态</button>
                </div>
            </div>

            <div id="faultResult" style="margin-top:24px;"></div>

            <div class="log-header">
                <div class="log-title">诊断日志</div>
            </div>
            <div class="log-box" id="logBox">工具已就绪</div>
        </div>
    </div>

    <footer>SAM｜5th tool, Ver 0.8 All interpretation rights reserved.</footer>
    <div class="loading" id="loading"><div class="loading-box"><div class="spinner"></div><div>处理中...</div></div></div>

<script>
    let currentLog = "工具已就绪";
    let maskSeed = "";
    function switchTab(idx){
        const seg = document.getElementById('segMain');
        seg.className = 'segmented seg-'+(idx+1);
        document.querySelectorAll('.seg-item').forEach(e=>e.classList.remove('active'));
        document.querySelectorAll('.seg-item')[idx].classList.add('active');
        document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
        document.getElementById('panel'+idx).classList.add('active');
        document.getElementById('faultResult').innerHTML='';
        resetSteps();
    }
    function showLoading(){document.getElementById('loading').style.display='flex';}
    function hideLoading(){document.getElementById('loading').style.display='none';}
    async function readDID(did){
        showLoading();
        let res=await fetch('/read',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({did})});
        let data=await res.json();
        let t=new Date().toLocaleTimeString();
        currentLog += `\\n\\n[${t}] ${did}诊断\\n`+data.log;
        document.getElementById('logBox').innerText=currentLog;
        document.getElementById('logBox').scrollTop=document.getElementById('logBox').scrollHeight;
        let dom=document.getElementById('faultResult');dom.innerHTML='';
        if(did==='FDA3'&&data.faults.length>0){
            dom.innerHTML=`<div class="fault-title">检测到故障：${data.faults.length} 个</div>`
            data.faults.forEach(i=>{
                dom.innerHTML += `<div class="fault-card"><div class="fault-name">${i.name}</div><div class="fault-desc">Byte ${i.byte} · Bit ${i.bit} | ${i.desc}</div></div>`;
            })
        }
        hideLoading();
    }
    function resetSteps(){document.querySelectorAll('.step-card').forEach(c=>c.classList.remove('step-done'));document.getElementById('seedShow').innerText='';document.getElementById('keyInput').value='';}
    function setStep(n){for(let i=1;i<=n;i++)document.getElementById('s'+i).classList.add('step-done');}
    async function startMask(){
        resetSteps();showLoading();
        let d=await (await fetch('/mask',{method:'POST',body:JSON.stringify({step:3}),headers:{'Content-Type':'application/json'}})).json();
        let t=new Date().toLocaleTimeString();
        currentLog += `\\n\\n[${t}] 屏蔽流程\\n`+d.log;
        document.getElementById('logBox').innerText=currentLog;
        document.getElementById('logBox').scrollTop=document.getElementById('logBox').scrollHeight;
        setStep(d.step);maskSeed=d.seed;document.getElementById('seedShow').innerText="Seed："+maskSeed;
        hideLoading();
    }
    async function sendKey(){
        let key=document.getElementById('keyInput').value.trim();
        if(!key)return alert("请输入密钥");
        showLoading();
        let d=await (await fetch('/mask',{method:'POST',body:JSON.stringify({step:6,key}),headers:{'Content-Type':'application/json'}})).json();
        let t=new Date().toLocaleTimeString();
        currentLog += `\\n\\n[${t}] 发送密钥解锁\\n`+d.log;
        document.getElementById('logBox').innerText=currentLog;
        document.getElementById('logBox').scrollTop=document.getElementById('logBox').scrollHeight;
        setStep(d.step);
        hideLoading();
    }
    async function sendCustomCmd(){
        let txt=document.getElementById('customCmdInput').value;
        if(!txt.trim())return alert("请输入UDS指令");
        showLoading();
        let res=await fetch('/customcmd',{method:'POST',body:JSON.stringify({cmd:txt}),headers:{'Content-Type':'application/json'}});
        let data=await res.json();
        let t=new Date().toLocaleTimeString();
        currentLog += `\\n\\n[${t}] 自定义批量诊断\\n`+data.log;
        document.getElementById('logBox').innerText=currentLog;
        document.getElementById('logBox').scrollTop=document.getElementById('logBox').scrollHeight;
        hideLoading();
    }
    function clearCustomInput(){document.getElementById('customCmdInput').value='';}
    function fillDemoCmd(){
        document.getElementById('customCmdInput').value=`1003
3E80
2701
2EFD00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF&#10;2EFD01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`;
    }
    async function readVehicleDtc(){
        showLoading();
        let d=await (await fetch('/readdtc')).json();
        let t=new Date().toLocaleTimeString();
        currentLog += `\\n\\n[${t}] 读取整车故障\\n`+d.log;
        document.getElementById('logBox').innerText=currentLog;
        document.getElementById('logBox').scrollTop=document.getElementById('logBox').scrollHeight;
        hideLoading();
    }
    async function clearVehicleDtc(){
        showLoading();
        let d=await (await fetch('/cleardtc')).json();
        let t=new Date().toLocaleTimeString();
        currentLog += `\\n\\n[${t}] 清除整车故障\\n`+d.log;
        document.getElementById('logBox').innerText=currentLog;
        document.getElementById('logBox').scrollTop=document.getElementById('logBox').scrollHeight;
        hideLoading();
    }
    async function refreshNetStatus(){
        let d=await (await fetch('/net')).json();
        let el=document.getElementById('status');
        if(d.connected){
            el.className='status-pill status-online';
            el.innerHTML='<div class="status-dot"></div><span>车端已连接</span>';
        }else{
            el.className='status-pill status-offline';
            el.innerHTML='<div class="status-dot"></div><span>车端未连接</span>';
        }
    }
    setInterval(refreshNetStatus,2000);
    window.onload=refreshNetStatus;
</script>
</body>
</html>
''')

# ====================== 接口 ======================
@app.route("/read", methods=["POST"])
def api_read_did():
    return jsonify(read_did(request.json.get("did", "")))

@app.route("/mask", methods=["POST"])
def api_mask_func():
    return jsonify(do_mask_process(request.json))

@app.route("/net")
def api_net_check():
    return jsonify({"connected": check_vehicle_connection()})

@app.route("/customcmd", methods=["POST"])
def api_custom_cmd():
    return jsonify({"log": send_custom_uds_cmds(request.json.get("cmd", ""))})

@app.route("/readdtc")
def api_read_dtc():
    return jsonify({"log": read_all_dtc()})

@app.route("/cleardtc")
def api_clear_dtc():
    return jsonify({"log": clear_all_dtc()})

# ====================== 启动 ======================
if __name__ == '__main__':
    def run_flask():
        app.run(host="127.0.0.1", port=SERVER_PORT, debug=False, use_reloader=False)
    threading.Thread(target=run_flask, daemon=True).start()
    time.sleep(1.5)
    webbrowser.open(f"http://127.0.0.1:{SERVER_PORT}")
    while True:
        time.sleep(1)