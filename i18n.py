"""화면 언어 (한국어 기본, 영어 선택). 번역 사전: i18n_en.json (화면 JS 와 같은 파일을 씀).

번역 방식: 숫자가 들어간 패턴 → 긴 문구부터 차례로 바꾼다. 사전에 없는 부분은 한국어로 남는다.
"""
import json
import os
import re

import config

_cache = {}


def _load():
    if "en" not in _cache:
        try:
            with open(os.path.join(config.RES_DIR, "i18n_en.json"), encoding="utf-8") as f:
                d = json.load(f)
            pats = [(re.compile(p), r.replace("$1", r"\g<1>").replace("$2", r"\g<2>")) for p, r in d.get("patterns", [])]
            phrases = sorted(d.get("phrases", []), key=lambda x: -len(x[0]))
            _cache["en"] = (pats, phrases)
        except Exception:
            _cache["en"] = ([], [])
    return _cache["en"]


def tr(text, lang):
    if lang != "en" or not text or not re.search("[가-힣]", text):
        return text
    pats, phrases = _load()
    # 1) 긴 문장 먼저 (숫자가 든 문장이 패턴에 먼저 쪼개지지 않게) → 2) 숫자+단위 패턴 → 3) 나머지 짧은 단어
    for ko, en in phrases:
        if len(ko) >= 6 and ko in text:
            text = text.replace(ko, en)
    for p, r in pats:
        text = p.sub(r, text)
    for ko, en in phrases:
        if len(ko) < 6 and ko in text:
            text = text.replace(ko, en)
    return text
