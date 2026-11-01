# -*- coding: utf-8 -*-
"""
SysScope CVE Audit（CVE 比對與 kernel 白話狀態）

兩件事：
1. kernel 白話狀態：正在跑哪個、已安裝最新的是哪個、有沒有「已更新但沒重開機」。
2. CVE 比對：輸入 CVE 編號，回「已修復／需更新／需重開機／尚無修補／未安裝」。

關鍵原則：
- 不拿「upstream 版本號 vs CVE 受影響範圍」比，因為發行版會 backport 修補。
  一律比「發行版公告的已修復套件版本」（資料來源 OSV.dev 的 Ubuntu / Debian 公告）。
- 版本比較用 dpkg 的演算法（epoch / upstream / revision / ~ 規則），不是字串或數字比較。
- 純標準函式庫；本模組自己不連網，連網只在 fetch_record() / build_pack()。
- 本模組只讀取與比對，從不修改主機。

目前支援：Ubuntu、Debian（dpkg 系）。RHEL 系尚未支援，遇到會明確回報「不支援」。
"""
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
UBUNTU_LTS = {"16.04", "18.04", "20.04", "22.04", "24.04", "26.04"}

# ----------------------------------------------------------------------------
# 1. dpkg 版本比較
# ----------------------------------------------------------------------------

def _order(c: str) -> int:
    if c == "~":
        return -1
    if c == "":
        return 0
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v: str) -> Tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    rev = ""
    if "-" in v:
        v, rev = v.rsplit("-", 1)
    return epoch, v, rev


def deb_compare(a: str, b: str) -> int:
    """回傳 <0 / 0 / >0（等同 dpkg --compare-versions）。"""
    ea, ua, ra = _split_version(a.strip())
    eb, ub, rb = _split_version(b.strip())
    if ea != eb:
        return ea - eb
    r = _verrevcmp(ua, ub)
    if r:
        return r
    return _verrevcmp(ra, rb)


# ----------------------------------------------------------------------------
# 2. 收集（貼上模式的一行指令 + 本機即時收集共用同一份格式）
# ----------------------------------------------------------------------------

COLLECTOR_ONELINER = (
    '(echo "=== [CVE_OS] ==="; cat /etc/os-release; '
    'echo "=== [CVE_KERNEL] ==="; echo "RUNNING=$(uname -r)"; echo "HOST=$(hostname)"; '
    'echo "NOW=$(date +%s)"; echo "UPTIME_SECONDS=$(cut -d\' \' -f1 /proc/uptime)"; '
    'if [ -f /var/run/reboot-required ]; then echo "REBOOT_REQUIRED=yes"; '
    'echo "REBOOT_SINCE=$(stat -c %Y /var/run/reboot-required)"; '
    'sed "s/^/REBOOT_PKG=/" /var/run/reboot-required.pkgs 2>/dev/null; '
    'else echo "REBOOT_REQUIRED=no"; fi; '
    'echo "=== [CVE_PKGS] ==="; '
    "dpkg-query -W -f='${Package} ${Version} ${source:Package} ${source:Version}\\n' 2>/dev/null; "
    'echo "=== [CVE_UPGRADES] ==="; apt-get -s dist-upgrade 2>/dev/null | grep "^Inst"; '
    'echo "=== [CVE_CPUVULN] ==="; grep -r . /sys/devices/system/cpu/vulnerabilities/ 2>/dev/null)'
)


def collect_local() -> str:
    """在本機（Linux）收集，輸出格式與 COLLECTOR_ONELINER 相同。純讀取。"""
    def sh(cmd: str, timeout: int = 60) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                               errors="ignore", timeout=timeout)
            return (r.stdout or "").rstrip("\n")
        except Exception:
            return ""

    return sh(COLLECTOR_ONELINER, timeout=120) + "\n"


def demux(bundle: str) -> Dict[str, str]:
    out: Dict[str, str] = {"OS": "", "KERNEL": "", "PKGS": "", "UPGRADES": "", "CPUVULN": ""}
    parts = re.split(r"===\s*\[?CVE_(OS|KERNEL|PKGS|UPGRADES|CPUVULN)\]?\s*===", bundle)
    for i in range(1, len(parts), 2):
        out[parts[i]] = parts[i + 1].strip("\n")
    return out


# ----------------------------------------------------------------------------
# 3. 解析
# ----------------------------------------------------------------------------

def parse_os(text: str) -> Dict[str, str]:
    kv = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip().strip('"')
    return kv


def osv_ecosystem(os_kv: Dict[str, str]) -> Optional[str]:
    """對應 OSV 的 ecosystem 名稱；不支援的發行版回傳 None。"""
    ident = (os_kv.get("ID") or "").lower()
    ver = os_kv.get("VERSION_ID", "")
    if ident == "ubuntu":
        return f"Ubuntu:{ver}:LTS" if ver in UBUNTU_LTS else f"Ubuntu:{ver}"
    if ident == "debian":
        return f"Debian:{ver.split('.')[0]}"
    return None


def parse_kernel_section(text: str) -> Dict[str, Any]:
    kv: Dict[str, Any] = {"reboot_pkgs": []}
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k == "REBOOT_PKG":
            kv["reboot_pkgs"].append(v.strip())
        else:
            kv[k] = v.strip()
    return kv


_KIMG = re.compile(r"^linux-image-(?:unsigned-)?(\d+\.\d+\.\d+-\d+)-([\w.+-]+)$")


def normalize_source(src: str) -> str:
    """linux-signed -> linux；linux-signed-hwe-5.15 -> linux-hwe-5.15（OSV 用的是原始 source 名）。"""
    s = re.sub(r"-signed(?=-|$)", "", src)
    s = re.sub(r"-restricted(?=-|$)", "", s)
    return s


def parse_pkgs(text: str) -> List[Dict[str, str]]:
    pkgs = []
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 4:
            pkgs.append({"name": p[0], "version": p[1], "source": normalize_source(p[2]), "source_version": p[3]})
        elif len(p) == 2:
            pkgs.append({"name": p[0], "version": p[1], "source": p[0], "source_version": p[1]})
    return pkgs


def parse_upgrades(text: str) -> List[Dict[str, Any]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"Inst (\S+)(?: \[([^\]]+)\])? \((\S+) ([^)]*)\)", line.strip())
        if m:
            origin = m.group(4)
            out.append({"name": m.group(1), "from": m.group(2) or "", "to": m.group(3),
                        "security": "security" in origin.lower(), "origin": origin})
    return out


def kernel_status(kernel_kv: Dict[str, Any], pkgs: List[Dict[str, str]],
                  upgrades: List[Dict[str, Any]]) -> Dict[str, Any]:
    running = kernel_kv.get("RUNNING", "")
    m = re.match(r"^(\d+\.\d+\.\d+-\d+)-([\w.+-]+)$", running)
    imgs = []
    for p in pkgs:
        mm = _KIMG.match(p["name"])
        if mm:
            imgs.append({"release": f"{mm.group(1)}-{mm.group(2)}", "flavor": mm.group(2),
                         "version": p["version"], "source": p["source"]})
    running_pkg = next((i for i in imgs if i["release"] == running), None)
    flavor = m.group(2) if m else None
    same = [i for i in imgs if i["flavor"] == flavor] or imgs
    newest = None
    for i in same:
        if newest is None or deb_compare(i["version"], newest["version"]) > 0:
            newest = i
    behind_installed = bool(running_pkg and newest and deb_compare(newest["version"], running_pkg["version"]) > 0)
    flagged = kernel_kv.get("REBOOT_REQUIRED") == "yes"
    pending_kernel_update = [u for u in upgrades if _KIMG.match(u["name"]) or re.match(r"^linux-(image|generic|signed)", u["name"])]

    days_pending = None
    try:
        if flagged and kernel_kv.get("REBOOT_SINCE") and kernel_kv.get("NOW"):
            days_pending = round((int(kernel_kv["NOW"]) - int(kernel_kv["REBOOT_SINCE"])) / 86400, 1)
    except ValueError:
        pass
    uptime_days = None
    try:
        uptime_days = round(float(kernel_kv.get("UPTIME_SECONDS", "")) / 86400, 1)
    except ValueError:
        pass

    return {
        "running": running,
        "running_version": running_pkg["version"] if running_pkg else None,
        "running_source": running_pkg["source"] if running_pkg else None,
        "newest_installed": newest["release"] if newest else None,
        "newest_installed_version": newest["version"] if newest else None,
        "reboot_flag": flagged,
        "reboot_packages": kernel_kv.get("reboot_pkgs", []),
        "reboot_pending": bool(flagged or behind_installed),
        "behind_installed": behind_installed,
        "reboot_pending_days": days_pending,
        "uptime_days": uptime_days,
        "pending_kernel_updates": [u["name"] for u in pending_kernel_update],
        "host": kernel_kv.get("HOST", ""),
    }


# ----------------------------------------------------------------------------
# 4. OSV 資料（線上 / 資料包）
# ----------------------------------------------------------------------------

def record_ids(cve: str, ecosystem: str) -> List[str]:
    cve = cve.strip().upper()
    if ecosystem.startswith("Ubuntu"):
        return [f"UBUNTU-{cve}"]
    if ecosystem.startswith("Debian"):
        return [f"DEBIAN-{cve}"]
    return [cve]


def slim_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """只留比對需要的欄位（資料包縮小用；丟掉 binaries 等大欄位）。"""
    aff = []
    for a in rec.get("affected", []):
        pkg = a.get("package") or {}
        if not pkg.get("ecosystem"):
            continue
        events = []
        for r in a.get("ranges", []):
            if r.get("type") not in ("ECOSYSTEM", None):
                continue
            events.append([(list(e.items())[0][0], list(e.items())[0][1]) for e in r.get("events", [])])
        aff.append({"ecosystem": pkg["ecosystem"], "package": pkg.get("name", ""), "ranges": events})
    priority = None
    for sv in rec.get("severity", []) or []:
        if sv.get("type") in ("Ubuntu", "Debian") and sv.get("score"):
            priority = str(sv["score"]).lower()
    return {"id": rec.get("id"), "upstream": rec.get("upstream", []) or rec.get("aliases", []),
            "summary": (rec.get("summary") or rec.get("details") or "")[:300], "priority": priority,
            "affected": aff}


def fetch_record(rec_id: str, timeout: int = 20) -> Optional[Dict[str, Any]]:
    """從 OSV.dev 取得單一公告。404 回 None；其他錯誤拋出 RuntimeError。"""
    req = urllib.request.Request(OSV_VULN_URL + rec_id, headers={"User-Agent": "SysScope-CVE/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return slim_record(json.loads(r.read().decode("utf-8")))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise RuntimeError(f"OSV 回應 HTTP {e.code}")
    except Exception as e:
        raise RuntimeError(f"無法連線 OSV：{type(e).__name__}")


_FIX_RE = re.compile(r"(?:before|prior to|earlier than|fixed in|patched in|resolved in)\s+v?(\d+\.\d+(?:\.\d+)*)", re.I)
_LAST_RE = re.compile(r"(?:through|up to(?: and including)?|<=)\s+v?(\d+\.\d+(?:\.\d+)*)"
                      r"|(\d+\.\d+(?:\.\d+)*)\s+and\s+(?:below|earlier|prior|older|lower)", re.I)


def version_hints(text: str) -> Dict[str, List[str]]:
    """從公告『文字』推測版本（啟發式，可能出錯，一律標示為推斷）。before X → 修復版本；through X → 最後受影響版本。"""
    return {"fixed_in": sorted(set(_FIX_RE.findall(text)), key=_dotted_key),
            "last_affected": sorted({a or b for a, b in _LAST_RE.findall(text)}, key=_dotted_key)}


def slim_generic(rec: Dict[str, Any]) -> Dict[str, Any]:
    text = (rec.get("summary") or "") + " " + (rec.get("details") or "")
    cvss = [sv.get("score", "") for sv in rec.get("severity", []) or [] if str(sv.get("type", "")).startswith("CVSS")]
    return {"id": rec.get("id"), "summary": (rec.get("summary") or rec.get("details") or "")[:300],
            "published": (rec.get("published") or "")[:10], "cvss": cvss[:1], "hints": version_hints(text)}


def fetch_generic(cve: str, timeout: int = 20) -> Optional[Dict[str, Any]]:
    """取得不分發行版的 CVE 記錄（OSV 的 CVE-xxxx）。404 回 None。"""
    req = urllib.request.Request(OSV_VULN_URL + cve, headers={"User-Agent": "SysScope-CVE/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return slim_generic(json.loads(r.read().decode("utf-8")))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise RuntimeError(f"OSV 回應 HTTP {e.code}")
    except Exception as e:
        raise RuntimeError(f"無法連線 OSV：{type(e).__name__}")


def _dotted(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0]))


def _dotted_key(v: str):
    return _dotted(v)


def evaluate_app_level(cve: str, generic: Dict[str, Any], app_version: Optional[str]) -> Dict[str, Any]:
    """應用程式層級 CVE（不是發行版套件，例如 LibreNMS 用 git 安裝）：只能依公告文字做『推斷』。"""
    res: Dict[str, Any] = {"cve": cve.upper(), "details": [], "summary": generic.get("summary", ""),
                           "published": generic.get("published", ""), "hints": generic.get("hints", {}),
                           "info_url": f"https://osv.dev/vulnerability/{cve.upper()}", "app_version": app_version}
    fixed = generic.get("hints", {}).get("fixed_in", [])
    last = generic.get("hints", {}).get("last_affected", [])
    res["note"] = ("Ubuntu / Debian 沒有此 CVE 的公告，但 CVE 本身存在：它多半是『應用程式』的漏洞（不是發行版套件，"
                   "例如用 git 或 docker 安裝的軟體），本工具無法用套件版本比對。")
    if not app_version:
        res["verdict"] = "APP_MANUAL"
        res["note"] += " 提供應用程式版本（--app-version / 網頁欄位）可做粗略推斷。"
        return res
    mine = _dotted(app_version)
    if fixed:
        target = max(fixed, key=_dotted_key)
        res["verdict"] = "APP_LIKELY_AFFECTED" if mine < _dotted(target) else "APP_LIKELY_FIXED"
        res["compare"] = f"你的版本 {app_version} 對照公告文字中的修復版本 {target}（依文字推斷，請人工核對）"
    elif last:
        target = max(last, key=_dotted_key)
        res["verdict"] = "APP_LIKELY_AFFECTED" if mine <= _dotted(target) else "APP_LIKELY_FIXED"
        res["compare"] = f"你的版本 {app_version} 對照公告文字中的最後受影響版本 {target}（依文字推斷，請人工核對）"
    else:
        res["verdict"] = "APP_MANUAL"
        res["note"] += " 公告文字沒有可辨識的版本資訊，請直接看公告。"
    return res


_DASHES = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe63\uff0d"), "-")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CVE_INPUT_LIMIT = 30


def parse_cve_input(raw: Any, limit: int = CVE_INPUT_LIMIT) -> Dict[str, Any]:
    """CVE 欄位『貼什麼都行』：CVE 編號、整頁網頁文字、新聞或群組訊息，一律自動挑出所有 CVE 編號。
    網頁複製常把連字號變成 en-dash / non-breaking hyphen，先統一成 '-'。依出現順序去重。"""
    if isinstance(raw, (list, tuple)):
        raw = " ".join(str(x) for x in raw)
    text = str(raw or "")
    seen: List[str] = []
    for m in _CVE_RE.findall(text.translate(_DASHES)):
        cid = m.upper()
        if cid not in seen:
            seen.append(cid)
    return {"ids": seen[:limit], "found": len(seen), "truncated": len(seen) > limit,
            "limit": limit, "had_input": bool(text.strip())}


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def osv_query_all(queries: List[Tuple[str, str, str]], max_pages: int = 6, timeout: int = 40):
    """一次問多個 (套件, ecosystem, 版本)：該版本受哪些公告影響。回傳 (每題的公告 id 集合, 被截斷的題號)。"""
    results: List[set] = [set() for _ in queries]
    pending = [(i, {"package": {"name": n, "ecosystem": e}, "version": v}) for i, (n, e, v) in enumerate(queries)]
    pages = 0
    try:
        while pending and pages < max_pages:
            pages += 1
            nxt = []
            for k in range(0, len(pending), 500):
                chunk = pending[k:k + 500]
                req = urllib.request.Request(OSV_BATCH_URL, data=json.dumps({"queries": [q for _, q in chunk]}).encode(),
                                             headers={"Content-Type": "application/json", "User-Agent": "SysScope-CVE/0.1"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.loads(r.read().decode("utf-8"))
                for (i, q), res in zip(chunk, data.get("results", [])):
                    for v in res.get("vulns", []) or []:
                        results[i].add(v["id"])
                    if res.get("next_page_token"):
                        q2 = dict(q)
                        q2["page_token"] = res["next_page_token"]
                        nxt.append((i, q2))
            pending = nxt
    except Exception as e:
        raise RuntimeError(f"無法連線 OSV：{type(e).__name__}")
    return results, {i for i, _ in pending}


def _cve_ids(ids) -> List[str]:
    out = set()
    for x in ids:
        m = re.search(r"(CVE-\d{4}-\d{4,})", x)
        if m:
            out.add(m.group(1))
    return sorted(out)


def auto_fixes(pkgs: List[Dict[str, str]], upgrades: List[Dict[str, Any]], ecosystem: str,
               max_packages: int = 40) -> Dict[str, Any]:
    """不用人輸入 CVE：對每個『待更新』的套件，問 OSV「目前版本受哪些公告影響」與「更新後版本受哪些影響」，
    兩者的差，就是這次更新會修掉的 CVE。資料每次都向 OSV 即時查詢。"""
    by_name = {p["name"]: p for p in pkgs}
    seen, items, queries = set(), [], []
    for u in upgrades:
        if not u["from"] or re.match(r"^linux-(image|headers|modules|generic|signed)", u["name"]):
            continue
        p = by_name.get(u["name"])
        if not p:
            continue
        key = (p["source"], p["source_version"], u["to"])
        if key in seen:
            continue
        seen.add(key)
        items.append({"source": p["source"], "installed": p["source_version"], "candidate": u["to"],
                      "security": u["security"], "binary": u["name"]})
        queries.append((p["source"], ecosystem, p["source_version"]))
        queries.append((p["source"], ecosystem, u["to"]))
        if len(items) >= max_packages:
            break
    out = {"items": [], "truncated": [], "total_cves": 0}
    if not items:
        return out
    res, trunc = osv_query_all(queries)
    total = set()
    for n, it in enumerate(items):
        before, after = res[2 * n], res[2 * n + 1]
        it["cves"] = _cve_ids(before - after)
        if (2 * n) in trunc or (2 * n + 1) in trunc:
            out["truncated"].append(it["source"])
        total.update(it["cves"])
        out["items"].append(it)
    out["total_cves"] = len(total)
    return out


def load_pack(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_pack(cves: List[str], ecosystems: List[str], out_path: str) -> Dict[str, Any]:
    """在『能上網』的機器上執行：把指定 CVE 的公告存成資料包，帶到離線環境使用。"""
    pack = {"built_at": int(time.time()), "records": {}, "missing": [], "generic": {}}
    for cve in cves:
        cve = cve.strip().upper()
        if cve not in pack["generic"]:
            g = fetch_generic(cve)
            if g:
                pack["generic"][cve] = g
        for eco in ecosystems:
            for rid in record_ids(cve, eco):
                if rid in pack["records"] or rid in pack["missing"]:
                    continue
                rec = fetch_record(rid)
                if rec is None:
                    pack["missing"].append(rid)
                else:
                    pack["records"][rid] = rec
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False)
    return pack


# ----------------------------------------------------------------------------
# 5. 比對
# ----------------------------------------------------------------------------

def range_status(version: str, ranges: List[List[Tuple[str, str]]]) -> Tuple[bool, Optional[str]]:
    """version 是否落在某個 introduced..fixed 之內。回傳 (有弱點, 該區間的修復版本或 None)。"""
    for events in ranges:
        start: Optional[str] = None
        for kind, val in events:
            if kind == "introduced":
                start = val
            elif kind == "fixed":
                if start is not None and (start == "0" or deb_compare(version, start) >= 0) \
                        and deb_compare(version, val) < 0:
                    return True, val
                start = None
        if start is not None and (start == "0" or deb_compare(version, start) >= 0):
            return True, None   # 有 introduced 沒 fixed：尚無修補
    return False, None


VERDICT_ORDER = ["UPDATE_NEEDED", "APP_LIKELY_AFFECTED", "NO_FIX_YET", "REBOOT_NEEDED", "FIXED", "APP_LIKELY_FIXED",
                 "NOT_INSTALLED", "APP_MANUAL", "UNKNOWN", "UNSUPPORTED"]
UNRESOLVED = ("UNKNOWN", "APP_MANUAL", "UNSUPPORTED")
VERDICT_TEXT = {
    "UPDATE_NEEDED": "尚未修補：需要更新套件",
    "NO_FIX_YET": "公告尚未列出修復版本（可能尚未修、不打算修、或低優先），請看公告頁確認",
    "REBOOT_NEEDED": "已安裝修補，但正在跑舊 kernel：需要重開機才生效",
    "FIXED": "已修復",
    "NOT_INSTALLED": "不受影響：未安裝相關套件",
    "UNKNOWN": "查無此 CVE 在該發行版的資料",
    "UNSUPPORTED": "此發行版尚未支援",
    "APP_LIKELY_AFFECTED": "應用程式層級 CVE：你的版本看起來低於修復版本（依公告文字推斷）",
    "APP_LIKELY_FIXED": "應用程式層級 CVE：你的版本看起來已不低於修復版本（依公告文字推斷，請人工核對）",
    "APP_MANUAL": "應用程式層級 CVE：本工具無法自動判斷，請看公告",
}


def evaluate_cve(cve: str, record: Optional[Dict[str, Any]], ecosystem: str,
                 pkgs: List[Dict[str, str]], kernel: Dict[str, Any],
                 upgrades: List[Dict[str, Any]]) -> Dict[str, Any]:
    res: Dict[str, Any] = {"cve": cve.upper(), "ecosystem": ecosystem, "details": [], "summary": ""}
    if record is None:
        res["verdict"] = "UNKNOWN"
        res["note"] = ("找不到此 CVE 的公告：可能編號有誤、太新（發行版還沒評估）、或不適用此發行版。"
                       "『查無』不等於『安全』。")
        return res
    res["summary"] = record.get("summary", "")
    res["priority"] = record.get("priority")
    res["info_url"] = (f"https://ubuntu.com/security/{res['cve']}" if ecosystem.startswith("Ubuntu")
                       else f"https://security-tracker.debian.org/tracker/{res['cve']}")
    entries = [a for a in record.get("affected", []) if a["ecosystem"] == ecosystem]
    if not entries:
        res["verdict"] = "UNKNOWN"
        res["note"] = (f"公告存在，但沒有 {ecosystem} 的條目。發行版通常會省略『不受影響』的版本，多半代表不受影響，"
                       "但這是推論，公告並沒有明講。")
        return res

    verdicts = []
    upg_names = {u["name"]: u for u in upgrades}
    for a in entries:
        src = a["package"]
        d: Dict[str, Any] = {"package": src}
        is_kernel = bool(kernel.get("running_source")) and src == kernel["running_source"]
        installed = [p for p in pkgs if p["source"] == src]
        kernel_imgs_here = src.startswith("linux") and any(_KIMG.match(p["name"]) for p in installed)
        if not installed:
            d["state"] = "NOT_INSTALLED"
            verdicts.append("NOT_INSTALLED")
            res["details"].append(d)
            continue

        if is_kernel or kernel_imgs_here:
            run_v = kernel.get("running_version") if is_kernel else None
            newest_v = kernel.get("newest_installed_version") if is_kernel else None
            if run_v is None:  # 沒在跑這個 source 的 kernel（例如裝了但用別的 flavor）
                ver_set = [p["source_version"] for p in installed if _KIMG.match(p["name"])]
                run_v = min(ver_set, key=lambda v: _key(v)) if ver_set else installed[0]["source_version"]
                newest_v = newest_v or run_v
            v_run, fix_run = range_status(run_v, a["ranges"])
            d.update({"running_version": run_v, "newest_installed_version": newest_v, "fixed_version": fix_run})
            if not v_run:
                d["state"] = "FIXED"
            else:
                v_new, fix_new = range_status(newest_v, a["ranges"]) if newest_v else (True, fix_run)
                if fix_run is None:
                    d["state"] = "NO_FIX_YET"
                elif not v_new:
                    d["state"] = "REBOOT_NEEDED"
                else:
                    d["state"] = "UPDATE_NEEDED"
                    d["update_available"] = bool(kernel.get("pending_kernel_updates"))
            verdicts.append(d["state"])
            res["details"].append(d)
            continue

        worst = None
        for p in installed:
            vuln, fixed = range_status(p["source_version"], a["ranges"])
            if vuln:
                worst = (p, fixed)
                break
        if worst is None:
            d["state"] = "FIXED"
            d["installed_version"] = installed[0]["source_version"]
        else:
            p, fixed = worst
            d["installed_version"] = p["source_version"]
            d["fixed_version"] = fixed
            d["state"] = "NO_FIX_YET" if fixed is None else "UPDATE_NEEDED"
            d["update_available"] = any(i["name"] in upg_names for i in installed)
            d["affected_binaries"] = [i["name"] for i in installed][:6]
        verdicts.append(d["state"])
        res["details"].append(d)

    for v in VERDICT_ORDER:
        if v in verdicts:
            res["verdict"] = v
            break
    else:
        res["verdict"] = "UNKNOWN"
    return res


def _key(v: str):
    import functools
    return functools.cmp_to_key(deb_compare)(v)


# ----------------------------------------------------------------------------
# 6. 彙整
# ----------------------------------------------------------------------------

LOW_PRIORITY = {"low", "negligible"}


def no_fix_matters(c: Dict[str, Any]) -> bool:
    """沒有修復版本的 CVE 是否值得警報：低優先度的舊 CVE 常是『不修』，不應讓排程天天叫。"""
    return c.get("verdict") == "NO_FIX_YET" and (c.get("priority") or "unknown") not in LOW_PRIORITY


class CVEAudit:
    def audit(self, bundle: str, cves: Optional[List[str]] = None, pack: Optional[Dict[str, Any]] = None,
              offline: bool = False, app_version: Optional[str] = None, auto: bool = False,
              cve_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        sec = demux(bundle)
        os_kv = parse_os(sec["OS"])
        eco = osv_ecosystem(os_kv)
        pkgs = parse_pkgs(sec["PKGS"])
        upgrades = parse_upgrades(sec["UPGRADES"])
        kernel = kernel_status(parse_kernel_section(sec["KERNEL"]), pkgs, upgrades)
        # 只算「已安裝套件有新版」；dist-upgrade 順帶新增的相依套件不算安全更新
        sec_updates = [u for u in upgrades if u["security"] and u["from"]]
        cpu_bad = []
        for line in sec["CPUVULN"].splitlines():
            m = re.search(r"/vulnerabilities/([\w]+):(.*)$", line)
            if m and m.group(2).strip().lower().startswith("vulnerable"):
                cpu_bad.append({"name": m.group(1), "status": m.group(2).strip()})

        result: Dict[str, Any] = {
            "host": kernel["host"],
            "os": os_kv.get("PRETTY_NAME", ""),
            "ecosystem": eco,
            "kernel": kernel,
            "pending_security_updates": [{"name": u["name"], "to": u["to"]} for u in sec_updates],
            "pending_updates_total": len([u for u in upgrades if u["from"]]),
            "pending_new_packages": len([u for u in upgrades if not u["from"]]),
            "cpu_vulnerabilities": cpu_bad,
            "cves": [],
            "errors": [],
            "cve_input": cve_input,
        }
        if eco is None:
            result["errors"].append(f"尚未支援的發行版：{os_kv.get('PRETTY_NAME', '未知')}（目前支援 Ubuntu / Debian）")

        for cve in (cves or []):
            cve = cve.strip().upper()
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
                result["cves"].append({"cve": cve, "verdict": "UNKNOWN", "details": [], "note": "CVE 編號格式不正確"})
                continue
            if eco is None:
                result["cves"].append({"cve": cve, "verdict": "UNSUPPORTED", "details": []})
                continue
            rec = None
            rid = record_ids(cve, eco)[0]
            try:
                if pack and rid in pack.get("records", {}):
                    rec = pack["records"][rid]
                elif pack and rid in pack.get("missing", []):
                    rec = None
                elif offline:
                    raise RuntimeError("離線模式且資料包內沒有這個 CVE")
                else:
                    rec = fetch_record(rid)
            except RuntimeError as e:
                result["errors"].append(f"{cve}：{e}")
                result["cves"].append({"cve": cve, "verdict": "UNKNOWN", "details": [], "note": str(e)})
                continue
            if rec is None:
                try:
                    gen = None
                    if pack and cve in pack.get("generic", {}):
                        gen = pack["generic"][cve]
                    elif not offline and not (pack and "generic" in pack):
                        gen = fetch_generic(cve)
                except RuntimeError as e:
                    gen = None
                    result["errors"].append(f"{cve}：{e}")
                if gen:
                    result["cves"].append(evaluate_app_level(cve, gen, app_version))
                    continue
            result["cves"].append(evaluate_cve(cve, rec, eco, pkgs, kernel, upgrades))

        result["auto_fixes"] = {"items": [], "truncated": [], "total_cves": 0}
        if auto and eco and not offline:
            try:
                result["auto_fixes"] = auto_fixes(pkgs, upgrades, eco)
            except RuntimeError as e:
                result["errors"].append(f"自動比對最新公告失敗：{e}")
        result["verdict"] = self._verdict(result)
        result["prescription"] = self._prescription(result)
        result["exit_code"] = self._exit_code(result)
        return result

    # ---- 結論（沿用 SysScope 其他模組的 verdict 格式：title/party/reason/action/color）
    @staticmethod
    def _verdict(r: Dict[str, Any]) -> Dict[str, str]:
        k = r["kernel"]
        states = [c["verdict"] for c in r["cves"]]
        need_update = "UPDATE_NEEDED" in states
        no_fix = any(no_fix_matters(c) for c in r["cves"])
        need_reboot = k["reboot_pending"] or "REBOOT_NEEDED" in states
        app_affected = [c["cve"] for c in r["cves"] if c["verdict"] == "APP_LIKELY_AFFECTED"]
        unresolved = [c["cve"] for c in r["cves"] if c["verdict"] in UNRESOLVED]
        days = k.get("reboot_pending_days")
        if r["errors"] and not r["cves"] and not r.get("ecosystem"):
            return {"title": "此發行版尚未支援", "party": "SysScope", "color": "#94a3b8",
                    "reason": r["errors"][0], "action": "目前僅支援 Ubuntu / Debian。"}
        if need_update:
            return {"title": "有 CVE 尚未修補，需要更新套件", "party": "系統管理員（排更新）", "color": "#ef4444",
                    "reason": "發行版已提供修復版本，但這台主機安裝的版本比它舊。",
                    "action": "依下方處方籤更新；若更新到 kernel，還要重開機才會生效。"}
        if app_affected:
            return {"title": f"有 {len(app_affected)} 個應用程式層級 CVE 看起來尚未修補", "party": "應用程式管理員", "color": "#ef4444",
                    "reason": "你提供的應用程式版本低於公告文字提到的修復版本（" + "、".join(app_affected[:4]) + "）。這是依文字推斷。",
                    "action": "請對照公告確認後，依該應用程式的官方方式更新。"}
        if need_reboot:
            since = f"（已等待 {days} 天）" if days is not None else ""
            return {"title": "已經更新過，但還沒重開機" + since, "party": "系統管理員（排重開機）", "color": "#f59e0b",
                    "reason": "新版 kernel 已安裝在硬碟，但主機還在跑舊的，修補其實還沒生效。",
                    "action": "排維護時段重開機；重開前先確認 /etc/fstab 與服務開機自啟（見『重開機安全驗收』）。"}
        if no_fix:
            return {"title": "有 CVE 發行版尚未提供修復", "party": "發行版維護者", "color": "#f59e0b",
                    "reason": "你已是最新，但發行版還沒釋出修復版本。",
                    "action": "評估緩解措施（停用相關模組／服務或防火牆限制），並追蹤公告。"}
        if r["pending_security_updates"]:
            n_cve = r.get("auto_fixes", {}).get("total_cves", 0)
            extra = f"，更新後會修掉 {n_cve} 個已公告的 CVE" if n_cve else ""
            return {"title": f"有 {len(r['pending_security_updates'])} 個安全更新待安裝{extra}", "party": "系統管理員", "color": "#f59e0b",
                    "reason": "發行版已提供修復，主機還沒裝。" + ("對應的 CVE 見下方清單。" if n_cve else ""),
                    "action": "排更新時間，見處方籤。"}
        ci = r.get("cve_input") or {}
        if ci.get("had_input") and ci.get("found", 0) == 0:
            return {"title": "你貼的內容裡沒有找到 CVE 編號", "party": "需要重貼", "color": "#f59e0b",
                    "reason": "CVE 編號的格式是 CVE-年份-數字（例如 CVE-2024-1086）。沒有找到，所以沒有做 CVE 比對。",
                    "action": "請確認貼的是含 CVE 編號的內容；或清空欄位，只看 kernel 與待更新套件。"}
        if unresolved:
            return {"title": f"有 {len(unresolved)} 筆 CVE 無法判斷（不等於安全）", "party": "需要人工確認", "color": "#f59e0b",
                    "reason": "這些 CVE 在發行版公告裡查無條目，工具沒辦法替你判斷有沒有中；沒有看到待重開機或待裝的安全更新。",
                    "action": "看下方每筆的說明：若是應用程式（如 LibreNMS）的 CVE，請輸入應用程式版本再比對，或直接看公告。"}
        return {"title": "未發現待處理的 CVE 或待重開機項目", "party": "—", "color": "#10b981",
                "reason": "所查 CVE 已修復或不受影響，且沒有待重開機、沒有待裝的安全更新。",
                "action": "維持例行更新即可。"}

    @staticmethod
    def _prescription(r: Dict[str, Any]) -> List[Dict[str, str]]:
        steps = []
        k = r["kernel"]
        states = [c["verdict"] for c in r["cves"]]
        if "UPDATE_NEEDED" in states or r["pending_security_updates"]:
            steps.append({"level": "P1", "title": "更新前：先做快照或備份",
                          "cmd": "（VM 快照；資料庫主機另做資料備份）",
                          "why": "更新可能動到 kernel 或核心函式庫，失敗時才能退回。"})
            steps.append({"level": "P1", "title": "更新套件清單並安裝",
                          "cmd": "sudo apt update && sudo apt upgrade",
                          "why": "安裝發行版已釋出的修復版本。請先看清單再按 Y。"})
        if k["reboot_pending"] or "UPDATE_NEEDED" in states or "REBOOT_NEEDED" in states:
            steps.append({"level": "P1", "title": "重開機前：確認這台重開機不會卡住",
                          "cmd": "cat /etc/fstab   # 貼到『重開機安全驗收』分頁；NFS 要有 _netdev,nofail",
                          "why": "跑很久沒重開的主機，最常死在 fstab 掛載。"})
            steps.append({"level": "P1", "title": "排維護時段重開機（叢集一次一台）",
                          "cmd": "sudo reboot",
                          "why": "新 kernel 要重開機才會啟用。"})
            steps.append({"level": "P2", "title": "重開後驗證",
                          "cmd": "uname -r; systemctl --failed",
                          "why": "uname -r 應等於或新於 " + str(k.get("newest_installed") or "已安裝的最新 kernel") +
                                 "；再用本工具重跑一次確認。"})
        if any(no_fix_matters(c) for c in r["cves"]):
            steps.append({"level": "P2", "title": "尚無修復：評估緩解",
                          "cmd": "（依 CVE 內容：停用模組、關閉服務、防火牆限制來源）",
                          "why": "發行版尚未提供修補，只能降低暴露面。"})
        if "APP_LIKELY_AFFECTED" in states:
            steps.append({"level": "P1", "title": "更新有漏洞的應用程式",
                          "cmd": "（依該應用程式的官方更新方式；更新前先備份其資料庫與設定）",
                          "why": "這類 CVE 不在 apt 更新範圍，apt upgrade 不會修它。"})
        if not steps:
            steps.append({"level": "OK", "title": "無需動作", "cmd": "—", "why": "維持例行更新。"})
        return steps

    @staticmethod
    def _exit_code(r: Dict[str, Any]) -> int:
        """給排程／NMS 用：0 正常；1 待重開機；2 有待修補（含無修復）；3 兩者都有；4 無法判斷。"""
        states = [c["verdict"] for c in r["cves"]]
        code = 0
        if r["kernel"]["reboot_pending"] or "REBOOT_NEEDED" in states:
            code |= 1
        if ("UPDATE_NEEDED" in states or "APP_LIKELY_AFFECTED" in states
                or any(no_fix_matters(c) for c in r["cves"]) or r["pending_security_updates"]):
            code |= 2
        ci = r.get("cve_input") or {}
        if code == 0 and (r["errors"] or any(x in states for x in UNRESOLVED)
                          or (ci.get("had_input") and ci.get("found", 0) == 0)):
            return 4
        return code

    @staticmethod
    def one_line(r: Dict[str, Any]) -> str:
        """單行摘要：可直接給 snmpd extend / 排程記錄用。"""
        k = r["kernel"]
        bad = [c["cve"] for c in r["cves"]
               if c["verdict"] in ("UPDATE_NEEDED", "REBOOT_NEEDED", "APP_LIKELY_AFFECTED") or no_fix_matters(c)]
        return (f"host={r['host'] or '?'} running={k['running']} reboot_pending={int(k['reboot_pending'])} "
                f"reboot_pending_days={k['reboot_pending_days'] if k['reboot_pending_days'] is not None else '-'} "
                f"security_updates={len(r['pending_security_updates'])} "
                f"cve_open={','.join(bad) if bad else '-'}")
