"""프로그램 바로 찾기 + 내 메모.

찾기: 이름 일부(예: agy, nosstarter, teamviewer)로
  - 실행 중인 프로세스
  - 설치된 프로그램 ('앱 제거' 목록)
  - 디스크의 실행 파일 (PATH 폴더, Program Files, AppData\\Local\\Programs 등 - 깊이·시간 제한)
  - 알고 있는 프로그램 사전 / 내 메모
를 한 번에 보여 주고, 각 항목에 종료·제거·삭제 버튼을 붙인다. (인터넷 조회는 하지 않음 - 화면에 검색 링크만)

메모: 프로그램 이름별로 사용자가 남긴 설명과 판단(safe/check/remove). kv 'user_notes'
"""
import os
import re
import time

import psutil

import procinfo
import remediate
import winutil

ADVICE_FROM_NOTE = {"safe": ("keep", "내가 확인한 안전한 프로그램"), "check": ("check", "확인 필요로 표시함"),
                    "remove": ("remove_rec", "삭제 예정으로 표시함")}


class Notes:
    def __init__(self, db):
        self.db = db
        self.reload()

    def reload(self):
        self.data = self.db.get("user_notes") or {}
        procinfo.PROCINFO.user_notes = self.data   # 프로세스 설명에 반영

    def set(self, name, note, verdict):
        key = (name or "").strip().lower()[:100]
        if not key:
            return {"ok": False, "msg": "이름이 없습니다"}
        if not note.strip() and verdict not in ADVICE_FROM_NOTE:
            self.data.pop(key, None)
            msg = f"'{name}' 메모를 지웠습니다"
        else:
            self.data[key] = {"name": name.strip()[:100], "note": note.strip()[:500],
                              "verdict": verdict if verdict in ADVICE_FROM_NOTE else "", "ts": int(time.time())}
            msg = f"'{name}' 메모를 저장했습니다"
        self.db.set("user_notes", self.data)
        self.reload()
        procinfo.PROCINFO.by_name.pop(key, None)
        return {"ok": True, "msg": msg}

    def list(self):
        return sorted(self.data.values(), key=lambda x: -x["ts"])


def _search_dirs():
    env = os.environ
    dirs = [d for d in env.get("PATH", "").split(";") if d and os.path.isdir(d)]
    dirs += [env.get("ProgramFiles", ""), env.get("ProgramFiles(x86)", ""), os.path.join(env.get("LOCALAPPDATA", ""), "Programs"),
             env.get("LOCALAPPDATA", ""), env.get("APPDATA", ""), os.path.join(env.get("USERPROFILE", ""), "Downloads"),
             os.path.join(env.get("USERPROFILE", ""), "Desktop"), env.get("ProgramData", "")]
    seen, out = set(), []
    for d in dirs:
        k = d.lower().rstrip("\\")
        if d and k not in seen and os.path.isdir(d) and not k.startswith(os.environ.get("SystemRoot", r"C:\Windows").lower()):
            seen.add(k)
            out.append(d)
    return out


def find_files(q, limit=15, budget=6.0):
    """실행 파일 이름에 q 가 들어간 것 (깊이 4, 최대 budget 초)."""
    q = q.lower()
    t0, hits = time.time(), []
    exts = (".exe", ".npe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".msi")
    for root in _search_dirs():
        base_depth = root.rstrip("\\").count("\\")
        for r, dirs, files in os.walk(root):
            if time.time() - t0 > budget or len(hits) >= limit:
                return hits, True
            if r.count("\\") - base_depth >= 4:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d.lower() not in ("node_modules", ".git", "cache", "winsxs", "__pycache__")]
            for f in files:
                fl = f.lower()
                if q in fl and fl.endswith(exts):
                    p = os.path.join(r, f)
                    if p.lower() not in (h.lower() for h in hits):
                        hits.append(p)
    return hits, False


class Finder:
    def __init__(self, mon):
        self.mon = mon

    def find(self, q):
        q = (q or "").strip()
        if len(q) < 2:
            return {"q": q, "error": "두 글자 이상 입력하세요"}
        ql = q.lower()
        rem, P = self.mon.rem, procinfo.PROCINFO
        out = {"q": q, "running": [], "installed": [], "files": [], "known": [], "notes": []}

        # 1) 실행 중
        groups = {}
        for p in psutil.process_iter(["pid", "name", "exe"]):
            n = p.info["name"] or ""
            if ql in n.lower():
                g = groups.setdefault((n.lower(), (p.info.get("exe") or "").lower()), {"name": n, "exe": p.info.get("exe") or "", "pids": []})
                g["pids"].append(p.info["pid"])
        for g in list(groups.values())[:10]:
            info = P.describe(g["pids"][0], g["name"], g["exe"])
            cpu = mem = 0.0
            for pid in g["pids"]:
                try:
                    pr = psutil.Process(pid)
                    mi = pr.memory_info()
                    mem += getattr(mi, "private", mi.rss) / 1048576
                except Exception:
                    pass
            row = {"name": g["name"], "pids": g["pids"], "mem_mb": round(mem), **info}
            row["actions"] = rem.proc_actions(row) if row.get("advice") else []
            out["running"].append(row)

        # 2) 설치된 프로그램
        for e in remediate.find_installed(ql)[:10]:
            cmd, silent = remediate._uninstall_cmd(e)
            a = {"id": rem.new_id("uninstall", e["hive"], e["key"]), "kind": "uninstall", "label": f"'{e['name']}' 제거",
                 "confirm": f"{e['name']} {e['version']} ({e['publisher']}) 를 제거합니다." + ("" if silent else "\n제거 창이 뜨면 안내에 따라 진행하세요."),
                 "cmd": cmd, "silent": silent, "entry": e}
            rem.extra[a["id"]] = a
            out["installed"].append({"name": e["name"], "version": e["version"], "publisher": e["publisher"], "actions": [a]})

        # 3) 디스크의 실행 파일
        files, partial = find_files(ql)
        running_exes = {g["exe"].lower() for g in groups.values()}
        sigs = winutil.signature_status(files[:12]) if files else {}
        for f in files:
            vs = procinfo.version_strings(f)
            s = sigs.get(f) or {}
            row = {"path": f, "name": os.path.basename(f), "desc": vs.get("FileDescription") or vs.get("ProductName") or "",
                   "company": vs.get("CompanyName", ""), "sig": s.get("s", ""), "signer": re.sub(r"^CN=\"?([^\",]+).*", r"\1", s.get("n") or ""),
                   "running": f.lower() in running_exes, "size_mb": round(os.path.getsize(f) / 1048576, 1) if os.path.exists(f) else 0}
            acts = []
            inst = remediate.find_installed(vs.get("ProductName"), f) if vs.get("ProductName") else remediate.find_installed(None, f)
            if len(inst) == 1:
                acts += rem.action_uninstall(inst[0]["name"], f)
            elif remediate.Remediator._quarantine_allowed(rem, f) and procinfo.advice_for(row["name"].lower(), {"cat": "", "company": row["company"]})[0] != "must":
                acts += [a for a in rem.action_delete(f)]
            for a in acts:
                rem.extra[a["id"]] = a
            row["actions"] = acts
            out["files"].append(row)
        out["files_partial"] = partial

        # 4) 알고 있는 프로그램 사전 / 내 메모
        for k, (desc, cat) in procinfo.KNOWN.items():
            if ql in k or ql in desc.lower():
                adv, txt = procinfo.advice_for(k, {"cat": cat, "company": "microsoft" if cat in ("시스템", "업데이트") else ""})
                out["known"].append({"name": k, "desc": desc, "cat": cat, "advice": adv, "advice_text": txt})
        for k, v in procinfo.KR_SECURITY.items():
            if ql in k or ql in v.lower():
                out["known"].append({"name": k + "*", "desc": v, "cat": "보안", "advice": "remove", "advice_text": procinfo.ADVICE_TEXT["remove"]})
        out["known"] = out["known"][:10]
        for n in self.mon.notes.list():
            if ql in n["name"].lower() or ql in n["note"].lower():
                out["notes"].append(n)
        return out
