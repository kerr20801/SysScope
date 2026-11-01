#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SysScope CVE 比對 — 命令列版（純標準函式庫，唯讀，不修改主機）

用法：
  python3 cve_check.py                          # 本機掃描：只看 kernel 與待安裝的安全更新
  python3 cve_check.py --cve CVE-2024-1086      # 同上，再比對指定 CVE（可多個）
  python3 cve_check.py --bundle 檔案.txt        # 分析貼回來的收集結果（-  代表 stdin）
  python3 cve_check.py --one-line               # 單行摘要（給排程 / snmpd extend / NMS）
  python3 cve_check.py --json                   # JSON 輸出
  python3 cve_check.py collector                # 印出『貼在目標主機上跑』的一行收集指令
  python3 cve_check.py build-pack --cve CVE-... [CVE-...] --eco Ubuntu:22.04:LTS Debian:12 --out pack.json
                                                # 在能上網的機器製作離線資料包
  --pack pack.json --offline                    # 離線環境使用資料包

結束碼（給排程判斷）：0 正常；1 待重開機；2 有待修補／安全更新；3 兩者都有；4 無法判斷。
"""
import argparse
import json
import os
import sys

import importlib.util  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_audit_module():
    """cve_audit.py 不依賴 SysScope 其他模組，所以單獨拷一份 cve_check.py + cve_audit.py 到任何主機都能跑
    （core/__init__.py 會載入其他模組，這裡刻意繞過它）。"""
    for cand in (os.path.join(_HERE, "cve_audit.py"), os.path.join(_HERE, "core", "cve_audit.py")):
        if os.path.exists(cand):
            spec = importlib.util.spec_from_file_location("cve_audit", cand)
            mod = importlib.util.module_from_spec(spec)
            sys.modules["cve_audit"] = mod
            spec.loader.exec_module(mod)
            return mod
    raise SystemExit("找不到 cve_audit.py（請與 cve_check.py 放在同一資料夾，或放在 core/ 下）")


_m = _load_audit_module()
CVEAudit, COLLECTOR_ONELINER, VERDICT_TEXT = _m.CVEAudit, _m.COLLECTOR_ONELINER, _m.VERDICT_TEXT
build_pack, collect_local, load_pack = _m.build_pack, _m.collect_local, _m.load_pack
parse_cve_input = _m.parse_cve_input

ICON = {"UPDATE_NEEDED": "🔴", "NO_FIX_YET": "🟠", "REBOOT_NEEDED": "🟡", "FIXED": "🟢",
        "NOT_INSTALLED": "⚪", "UNKNOWN": "❔", "UNSUPPORTED": "⚪",
        "APP_LIKELY_AFFECTED": "🔴", "APP_LIKELY_FIXED": "🟢", "APP_MANUAL": "❔"}


def render(r: dict) -> str:
    k = r["kernel"]
    out = []
    out.append(f"主機：{r['host'] or '?'}　系統：{r['os'] or '?'}")
    out.append("")
    out.append("【Kernel 狀態】")
    out.append(f"  正在跑的 kernel      ：{k['running']}（套件版本 {k['running_version'] or '?'}）")
    out.append(f"  已安裝的最新 kernel  ：{k['newest_installed'] or '?'}（{k['newest_installed_version'] or '?'}）")
    if k["reboot_pending"]:
        why = []
        if k["behind_installed"]:
            why.append("已安裝較新的 kernel 但還沒用上")
        if k["reboot_flag"]:
            pk = "、".join(k["reboot_packages"]) if k["reboot_packages"] else "系統標記"
            why.append(f"系統要求重開機（{pk}）")
        days = f"，已等待 {k['reboot_pending_days']} 天" if k["reboot_pending_days"] is not None else ""
        out.append(f"  ⚠️ 待重開機          ：是（{'；'.join(why)}{days}）")
    else:
        out.append("  待重開機            ：否")
    if k["uptime_days"] is not None:
        out.append(f"  已連續開機          ：{k['uptime_days']} 天")
    if k["pending_kernel_updates"]:
        out.append(f"  待安裝的 kernel 更新：{', '.join(k['pending_kernel_updates'][:4])}")
    out.append("")
    out.append(f"【待安裝的安全更新】{len(r['pending_security_updates'])} 個（全部待更新 {r['pending_updates_total']} 個，另有新增套件 {r['pending_new_packages']} 個）")
    for u in r["pending_security_updates"][:10]:
        out.append(f"  - {u['name']} → {u['to']}")
    af = r.get("auto_fixes", {})
    if af.get("items"):
        out.append("")
        out.append(f"【待更新的套件，更新後會修掉的 CVE（自動比對最新公告，共 {af['total_cves']} 個）】")
        for it in af["items"]:
            tag = "安全" if it["security"] else "一般"
            cv = "、".join(it["cves"][:8]) + (f" …等 {len(it['cves'])} 個" if len(it["cves"]) > 8 else "") if it["cves"] else "（公告中沒有對應的 CVE）"
            out.append(f"  - [{tag}] {it['source']} {it['installed']} → {it['candidate']}：{cv}")
        if af.get("truncated"):
            out.append(f"  （{', '.join(af['truncated'])} 的公告太多，只比對了前幾頁，清單可能不完整）")
    if r["cpu_vulnerabilities"]:
        out.append("")
        out.append("【CPU 弱點狀態：標示為 Vulnerable 的項目】")
        for c in r["cpu_vulnerabilities"]:
            out.append(f"  - {c['name']}: {c['status']}")
    ci = r.get("cve_input") or {}
    if ci.get("had_input"):
        out.append("")
        if ci["found"]:
            cut = f"，只比對前 {ci['limit']} 個" if ci["truncated"] else ""
            out.append(f"【從你輸入的內容找到 {ci['found']} 個 CVE{cut}】")
        else:
            out.append("【你輸入的內容裡沒有找到 CVE 編號（格式應為 CVE-2024-1234）】")
    if r["cves"]:
        out.append("")
        out.append("【CVE 比對】")
        for c in r["cves"]:
            out.append(f"  {ICON.get(c['verdict'], '')} {c['cve']}：{VERDICT_TEXT.get(c['verdict'], c['verdict'])}")
            for d in c.get("details", []):
                if d["state"] == "NOT_INSTALLED":
                    continue
                bits = [f"套件 {d['package']}"]
                if d.get("running_version"):
                    bits.append(f"正在跑 {d['running_version']}")
                if d.get("installed_version"):
                    bits.append(f"已安裝 {d['installed_version']}")
                if d.get("newest_installed_version") and d.get("newest_installed_version") != d.get("running_version"):
                    bits.append(f"已裝最新 {d['newest_installed_version']}")
                if d.get("fixed_version"):
                    bits.append(f"修復版本 {d['fixed_version']}")
                out.append("      " + "，".join(bits))
            if c.get("compare"):
                out.append(f"      {c['compare']}")
            if c["verdict"].startswith("APP_"):
                out.append(f"      摘要：{c.get('summary', '')}（公告發布 {c.get('published', '?')}）　{c.get('info_url')}")
            if c["verdict"] == "NO_FIX_YET":
                out.append(f"      Ubuntu/Debian 優先度：{c.get('priority') or '未標示'}　公告：{c.get('info_url')}")
            if c.get("note"):
                out.append(f"      {c['note']}")
    if r["errors"]:
        out.append("")
        out.append("【提醒】")
        for e in r["errors"]:
            out.append(f"  - {e}")
    v = r["verdict"]
    out.append("")
    out.append(f"結論：{v['title']}")
    out.append(f"  原因：{v['reason']}")
    out.append(f"  建議：{v['action']}")
    out.append("")
    out.append("【處方籤】")
    for s in r["prescription"]:
        out.append(f"  [{s['level']}] {s['title']}")
        out.append(f"        指令：{s['cmd']}")
        out.append(f"        原因：{s['why']}")
    return "\n".join(out)


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "collector":
        print(COLLECTOR_ONELINER)
        return 0
    if argv and argv[0] == "build-pack":
        ap = argparse.ArgumentParser(prog="cve_check.py build-pack")
        ap.add_argument("--cve", nargs="+", required=True)
        ap.add_argument("--eco", nargs="+", default=["Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS", "Debian:12"])
        ap.add_argument("--out", required=True)
        a = ap.parse_args(argv[1:])
        pack = build_pack(a.cve, a.eco, a.out)
        print(f"資料包已寫入 {a.out}：{len(pack['records'])} 筆公告，{len(pack['missing'])} 筆查無")
        return 0

    ap = argparse.ArgumentParser(description="SysScope CVE 比對（唯讀）")
    ap.add_argument("--cve", nargs="*", default=[], help="CVE 編號（也可貼任何含 CVE 編號的文字，會自動挑出來）")
    ap.add_argument("--cve-file", help="含 CVE 編號的任意文字檔（網頁複製、新聞、公告皆可；- 為 stdin）")
    ap.add_argument("--bundle", help="收集結果檔案（- 為 stdin）")
    ap.add_argument("--pack", help="離線資料包 JSON")
    ap.add_argument("--app-version", help="應用程式版本（例如 LibreNMS 的 26.10.0），用來粗略比對應用程式層級的 CVE")
    ap.add_argument("--offline", action="store_true", help="不連網；只用資料包")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--one-line", action="store_true")
    a = ap.parse_args(argv)

    if a.bundle:
        bundle = sys.stdin.read() if a.bundle == "-" else open(a.bundle, encoding="utf-8", errors="ignore").read()
    else:
        if not sys.platform.startswith("linux"):
            print("本機掃描只支援 Linux。請在目標主機執行 `python3 cve_check.py collector` 印出的指令，"
                  "把結果存檔後用 --bundle 分析。", file=sys.stderr)
            return 4
        bundle = collect_local()

    pack = load_pack(a.pack) if a.pack else None
    raw = " ".join(a.cve)
    if a.cve_file:
        raw += "\n" + (sys.stdin.read() if a.cve_file == "-" else open(a.cve_file, encoding="utf-8", errors="ignore").read())
    info = parse_cve_input(raw)
    r = CVEAudit().audit(bundle, cves=info["ids"], pack=pack, offline=a.offline, app_version=a.app_version,
                         auto=(not info["had_input"] and not a.offline), cve_input=info)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    elif a.one_line:
        print(CVEAudit.one_line(r))
    else:
        print(render(r))
    return r["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
