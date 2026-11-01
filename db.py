"""SQLite 저장소 + 보관기간 정리."""
import json
import os
import sqlite3
import threading
import time

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics(
  ts INTEGER PRIMARY KEY, cpu REAL, mem REAL, mem_used_mb INTEGER, commit_pct REAL,
  disk_busy REAL, disk_r REAL, disk_w REAL, net_rx REAL, net_tx REAL,
  procs INTEGER, handles INTEGER, threads INTEGER);
CREATE TABLE IF NOT EXISTS metrics_5m(
  ts INTEGER PRIMARY KEY, cpu_avg REAL, cpu_max REAL, mem_avg REAL, mem_max REAL,
  commit_max REAL, disk_busy_max REAL, net_rx REAL, net_tx REAL);
CREATE TABLE IF NOT EXISTS procs(
  ts INTEGER, kind TEXT, rank INTEGER, pid INTEGER, name TEXT, cpu REAL, mem_mb REAL);
CREATE INDEX IF NOT EXISTS procs_ts ON procs(ts);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, category TEXT, severity TEXT,
  source TEXT, event_id INTEGER, title TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, key TEXT, severity TEXT, title TEXT, body TEXT);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, last_heartbeat INTEGER, boot_time INTEGER,
  kind TEXT, bugcheck TEXT, summary TEXT, snapshot TEXT);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS fw_drops(ts INTEGER, src TEXT, n INTEGER, ports TEXT, kind TEXT, proto TEXT);
CREATE INDEX IF NOT EXISTS fw_drops_ts ON fw_drops(ts);
"""


class DB:
    def __init__(self, path=config.DB_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        new = not os.path.exists(path)
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        if new:
            # 지운 공간을 실제로 돌려받을 수 있게 (VACUUM 없이)
            self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA journal_size_limit=4000000")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------- 기본 ----------
    def execute(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur

    def query(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def get(self, k, default=None):
        rows = self.query("SELECT v FROM kv WHERE k=?", (k,))
        if not rows:
            return default
        try:
            return json.loads(rows[0]["v"])
        except Exception:
            return default

    def set(self, k, v):
        self.execute("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", (k, json.dumps(v, ensure_ascii=False)))

    # ---------- 쓰기 ----------
    def add_metric(self, m, heartbeat_ts):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO metrics VALUES(:ts,:cpu,:mem,:mem_used_mb,:commit_pct,:disk_busy,"
                ":disk_r,:disk_w,:net_rx,:net_tx,:procs,:handles,:threads)", m)
            self.conn.execute("INSERT OR REPLACE INTO kv(k,v) VALUES('heartbeat',?)", (str(heartbeat_ts),))
            self.conn.commit()

    def add_procs(self, ts, rows):
        with self.lock:
            self.conn.executemany("INSERT INTO procs VALUES(?,?,?,?,?,?,?)",
                                  [(ts, r["kind"], r["rank"], r["pid"], r["name"], r["cpu"], r["mem_mb"]) for r in rows])
            self.conn.commit()

    def add_event(self, ts, category, severity, source, event_id, title, detail=""):
        if not isinstance(detail, str):
            detail = json.dumps(detail, ensure_ascii=False)
        self.execute("INSERT INTO events(ts,category,severity,source,event_id,title,detail) VALUES(?,?,?,?,?,?,?)",
                     (int(ts), category, severity, source, event_id, title, detail[:4000]))

    # ---------- 5분 요약 ----------
    def aggregate(self):
        last = self.get("last_agg", 0)
        upto = int(time.time()) // 300 * 300  # 끝난 5분 구간까지만
        if upto <= last:
            return
        with self.lock:
            self.conn.execute("""
              INSERT OR REPLACE INTO metrics_5m
              SELECT (ts/300)*300, AVG(cpu), MAX(cpu), AVG(mem), MAX(mem), MAX(commit_pct),
                     MAX(disk_busy), AVG(net_rx), AVG(net_tx)
              FROM metrics WHERE ts>=? AND ts<? GROUP BY ts/300""", (last, upto))
            self.conn.commit()
        self.set("last_agg", upto)

    # ---------- 정리 ----------
    def size_mb(self):
        total = 0
        for suffix in ("", "-wal"):
            p = self.path + suffix
            if os.path.exists(p):
                total += os.path.getsize(p)
        return total / 1e6

    def cleanup(self):
        now = int(time.time())
        raw = now - config.KEEP_RAW_DAYS * 86400
        agg = now - config.KEEP_5MIN_DAYS * 86400
        ev = now - config.KEEP_EVENT_DAYS * 86400
        with self.lock:
            c = self.conn
            c.execute("DELETE FROM metrics WHERE ts<?", (raw,))
            c.execute("DELETE FROM procs WHERE ts<?", (raw,))
            c.execute("DELETE FROM metrics_5m WHERE ts<?", (agg,))
            c.execute("DELETE FROM fw_drops WHERE ts<?", (now - config.KEEP_FW_DAYS * 86400,))
            for t in ("events", "alerts", "incidents"):
                c.execute(f"DELETE FROM {t} WHERE ts<?", (ev,))
            c.commit()
            # 상한 초과 시 원본/이벤트를 오래된 쪽부터 절반씩 줄인다
            for _ in range(5):
                c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                c.execute("PRAGMA incremental_vacuum")
                c.commit()
                if self.size_mb() <= config.DB_MAX_MB:
                    break
                for t in ("procs", "fw_drops", "metrics", "events", "metrics_5m"):
                    row = c.execute(f"SELECT MIN(ts), MAX(ts) FROM {t}").fetchone()
                    if row[0] is not None:
                        c.execute(f"DELETE FROM {t} WHERE ts<?", ((row[0] + row[1]) // 2,))
                c.commit()
