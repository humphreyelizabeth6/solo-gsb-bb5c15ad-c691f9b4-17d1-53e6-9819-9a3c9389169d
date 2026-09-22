"""规则审计修复引擎（纯函数，无副作用，不依赖 FastAPI / SQLite）。

基于 :func:`app.audit.audit_rules` 的覆盖关系，为 **动作冲突 / 完全遮蔽 /
冗余重叠** 三类关系生成确定性的 *合并* 或 *收窄* 建议（冷却差异涉及业务
取舍，不自动生成建议）：

- ``merge_into_higher``  冗余重叠：两条规则动作/冷却一致，把低优先级规则的
                        可达域并入高优先级规则（条件取并集），并停用低优先级
                        规则。交集非空时并集一定能表达为单条规则（字段取较宽
                        者、日期取首尾、时段合并后仍是合法窗口）；
- ``narrow_lower_time`` / ``narrow_lower_dates``
                        收窄低优先级规则的每日时段 / 日期范围，使其与高优先
                        级规则在该维度上不再相交，整组关系随之消除（仅当收窄
                        结果能用单条规则精确表达时才生成）；
- ``disable_lower``     停用低优先级规则：完全遮蔽的死规则停用后不改变任何
                        评估结果；动作冲突中停用后交集冲突消失。

每条建议附带 **确定性预演**：在规则副本上模拟应用后重新审计，给出"解决
哪些关系 / 新增哪些关系"，与真正应用时的前后对比口径完全一致。

确定性保证
----------
- 建议只取决于当前规则集合：同一规则集在任何时刻生成完全相同的建议
  （建议 id 为内容哈希），与调用时机、告警数据、live/replay 历史无关；
- 本模块不读写任何数据库表；应用、校验与回滚由 ``main.py`` 在单事务内完成。
"""
from __future__ import annotations

import hashlib
import json
from datetime import date, timedelta
from typing import Optional, Sequence

from .audit import (
    DAY_MINUTES,
    TimeDomain,
    _EMPTY,
    _hm,
    _merge_segments,
    _norm_rule,
    audit_rules,
    date_intersect,
    describe_date,
    describe_time,
)

# 建议类型
KIND_LABELS = {
    "merge_into_higher": "合并规则",
    "narrow_lower_time": "收窄时段",
    "narrow_lower_dates": "收窄日期",
    "disable_lower": "停用规则",
}

# 生成建议的冲突类型（冷却差异不在自动修复范围内）
FIXABLE_TYPES = ("action_conflict", "shadowed", "redundant_overlap")

_KIND_ORDER = {
    "merge_into_higher": 0,
    "narrow_lower_time": 1,
    "narrow_lower_dates": 2,
    "disable_lower": 3,
}

# update_rule 操作允许写入的规则字段（DB 列名）
ALLOWED_OP_FIELDS = {
    "match_device", "match_batch", "match_level",
    "time_start", "time_end", "date_start", "date_end", "description",
}


# ---------------------------------------------------------------------------
# 关系键与审计差异
# ---------------------------------------------------------------------------

def relation_key(overlap: dict) -> tuple:
    """一条审计关系的稳定身份：(较小规则 id, 较大规则 id, 冲突类型)。"""
    ids = overlap["rule_ids"]
    return (min(ids), max(ids), overlap["conflict_type"])


def brief_relation(overlap: dict) -> dict:
    """关系的轻量摘要（用于建议预演与修复历史展示）。"""
    return {
        "rule_ids": list(overlap["rule_ids"]),
        "conflict_type": overlap["conflict_type"],
        "conflict_label": overlap["conflict_label"],
    }


def audit_diff(before: dict, after: dict) -> dict:
    """两次审计结果的确定性差异：已解决 / 新引入 / 仍存在的关系。"""
    b = {relation_key(o): o for o in before.get("overlaps", [])}
    a = {relation_key(o): o for o in after.get("overlaps", [])}
    resolved = [b[k] for k in sorted(b.keys() - a.keys())]
    introduced = [a[k] for k in sorted(a.keys() - b.keys())]
    return {
        "resolved": resolved,
        "introduced": introduced,
        "resolved_count": len(resolved),
        "introduced_count": len(introduced),
        "remaining_count": len(b.keys() & a.keys()),
        "before_total": len(b),
        "after_total": len(a),
        "before_totals": before.get("totals", {}),
        "after_totals": after.get("totals", {}),
    }


# ---------------------------------------------------------------------------
# 时段 / 日期的收窄与窗口表达
# ---------------------------------------------------------------------------

def _subtract_segments(base: Sequence[tuple[int, int]],
                       cuts: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """从 base 区间集合中减去 cuts（分钟粒度闭区间），返回合并后的余量。"""
    merged_cuts = _merge_segments([tuple(c) for c in cuts])
    out: list[tuple[int, int]] = []
    for s, e in sorted(base):
        cur = s
        for cs, ce in merged_cuts:
            if ce < cur or cs > e:
                continue
            if cs > cur:
                out.append((cur, cs - 1))
            cur = max(cur, ce + 1)
            if cur > e:
                break
        if cur <= e:
            out.append((cur, e))
    return _merge_segments(out)


def _domain_to_window(domain: TimeDomain) -> Optional[tuple[str, str]]:
    """把可达时段转换回规则的 (time_start, time_end)；无法精确表达时返回 None。

    可表达的形式：全天、单段同日窗口、跨午夜对（[s,24:00] ∪ [0,e]）。
    单时刻、单侧到午夜等形态无法用一条规则精确表达（起=止会被视为全天）。
    """
    segs = sorted(domain.segments)
    if not segs:
        return None
    if len(segs) == 1:
        s, e = segs[0]
        if (s, e) == (0, DAY_MINUTES):
            return ("", "")
        if s >= e or e >= DAY_MINUTES:
            return None
        return (_hm(s), _hm(e))
    if len(segs) == 2:
        (s1, e1), (s2, e2) = segs
        if s1 == 0 and e2 == DAY_MINUTES and e1 < s2 < DAY_MINUTES:
            return (_hm(s2), _hm(e1))  # 跨午夜窗口
        return None
    return None


def _narrow_dates(lo_start: str, lo_end: str,
                  hi_start: str, hi_end: str) -> Optional[tuple[str, str]]:
    """收窄低优先级规则的日期范围，使其与高优先级规则的日期不再相交。

    余量 = 低优先级日期范围减去交集。仅当余量是单个连续区间（交集贴着某一
    侧边界）时才能用一条规则表达；两侧都有余量或余量为空时返回 None。
    """
    isect = date_intersect(lo_start, lo_end, hi_start, hi_end)
    if isect is _EMPTY:
        return None  # 已不相交，无需收窄（正常流程不会走到）
    is_start, is_end = isect

    left: Optional[tuple[str, str]] = None
    if is_start:  # 交集有下界 → 左侧余量 [lo_start, 交集起点-1天]
        day = (date.fromisoformat(is_start) - timedelta(days=1)).isoformat()
        if not lo_start or lo_start <= day:
            left = (lo_start, day)
    right: Optional[tuple[str, str]] = None
    if is_end:  # 交集有上界 → 右侧余量 [交集终点+1天, lo_end]
        day = (date.fromisoformat(is_end) + timedelta(days=1)).isoformat()
        if not lo_end or day <= lo_end:
            right = (day, lo_end)

    if left and right:
        return None  # 余量分成两段，单条规则无法表达
    return left or right


def _reach_summary(device: Optional[str], batch: Optional[str],
                   level: Optional[str], domain: TimeDomain,
                   date_start: str, date_end: str) -> str:
    f = lambda v: "*" if v is None else v  # noqa: E731
    return (f"设备 {f(device)} · 批次 {f(batch)} · 级别 {f(level)} · "
            f"时段 {describe_time(domain)} · 日期 {describe_date(date_start, date_end)}")


# ---------------------------------------------------------------------------
# 建议构建
# ---------------------------------------------------------------------------

def _base_suggestion(o: dict, kind: str, title: str, detail: str,
                     ops: list[dict], affected: list[int]) -> dict:
    return {
        "id": "",  # 生成后按内容哈希回填
        "kind": kind,
        "kind_label": KIND_LABELS[kind],
        "conflict_type": o["conflict_type"],
        "conflict_label": o["conflict_label"],
        "relation_key": list(relation_key(o)),
        "rule_ids": list(o["rule_ids"]),
        "affected_rule_ids": affected,
        "title": title,
        "detail": detail,
        "ops": ops,
    }


def _disable_suggestion(o: dict, hi: dict, lo: dict) -> dict:
    if o["conflict_type"] == "shadowed":
        detail = (
            f"#{lo['id']} 的可达条件被 #{hi['id']} 完全包含且动作/冷却一致，"
            "它永远不会成为命中规则（死规则）；停用后不改变任何评估结果，"
            "规则行保留、可随时撤销"
        )
    else:
        detail = (
            f"#{lo['id']} 与 #{hi['id']} 存在{o['conflict_label']}，交集内它的动作"
            f"永远被 #{hi['id']} 改写；停用后冲突消失。注意：交集之外原本由 "
            f"#{lo['id']} 处理的告警将改由后续规则或默认策略（放行）处理"
        )
    return _base_suggestion(
        o, "disable_lower",
        f"停用 #{lo['id']}「{lo['name']}」",
        detail,
        [{"op": "disable_rule", "rule_id": lo["id"]}],
        [lo["id"]],
    )


def _merge_suggestion(o: dict, hi: dict, lo: dict) -> Optional[dict]:
    """冗余重叠的合并建议：高优先级规则条件拓宽为并集，低优先级规则停用。"""
    # 字段并集：交集非空 ⇒ 相同或其一通配，并集即较宽者（None=通配）
    device = hi["device"] if hi["device"] == lo["device"] else None
    batch = hi["batch"] if hi["batch"] == lo["batch"] else None
    level = hi["level"] if hi["level"] == lo["level"] else None
    # 时段并集：两条相交窗口合并后仍是合法窗口（全天 / 单段 / 跨午夜对）
    union_domain = TimeDomain(tuple(_merge_segments(
        list(hi["time"].segments) + list(lo["time"].segments)
    )))
    window = _domain_to_window(union_domain)
    if window is None:
        return None  # 理论不可达（相交窗口的并集必可表达），防御性跳过
    # 日期并集：交集非空 ⇒ [较早起点, 较晚终点] 精确等于并集（空串=无界）
    date_start = "" if not hi["date_start"] or not lo["date_start"] \
        else min(hi["date_start"], lo["date_start"])
    date_end = "" if not hi["date_end"] or not lo["date_end"] \
        else max(hi["date_end"], lo["date_end"])

    summary = _reach_summary(device, batch, level, union_domain, date_start, date_end)
    fields = {
        "match_device": device or "",
        "match_batch": batch or "",
        "match_level": level or "",
        "time_start": window[0],
        "time_end": window[1],
        "date_start": date_start,
        "date_end": date_end,
        "description": (hi["description"] + f"（已并入 #{lo['id']} 的可达域）")[:300],
    }
    detail = (
        f"两条规则动作与冷却一致。把 #{hi['id']} 的条件拓宽为两规则可达域的并集"
        f"（{summary}），并停用 #{lo['id']}；两规则原有覆盖范围内的评估结果不变。"
        "注意：拓宽后可能与第三条规则产生新的关系，请查看预演中的「新增的关系」"
    )
    return _base_suggestion(
        o, "merge_into_higher",
        f"将 #{lo['id']}「{lo['name']}」并入 #{hi['id']}「{hi['name']}」",
        detail,
        [{"op": "update_rule", "rule_id": hi["id"], "fields": fields},
         {"op": "disable_rule", "rule_id": lo["id"]}],
        [hi["id"], lo["id"]],
    )


def _narrow_suggestions(o: dict, hi: dict, lo: dict) -> list[dict]:
    """收窄低优先级规则，使其在某一维度上与高优先级规则不再相交。"""
    out: list[dict] = []

    # 日期维度：余量须为单个连续区间
    narrowed = _narrow_dates(lo["date_start"], lo["date_end"],
                             hi["date_start"], hi["date_end"])
    if narrowed is not None and narrowed != (lo["date_start"], lo["date_end"]):
        ds, de = narrowed
        out.append(_base_suggestion(
            o, "narrow_lower_dates",
            f"收窄 #{lo['id']}「{lo['name']}」的日期范围为 {describe_date(ds, de)}",
            (f"#{lo['id']} 的日期范围由 {describe_date(lo['date_start'], lo['date_end'])} "
             f"收窄为 {describe_date(ds, de)}，与 #{hi['id']} 的日期"
             f"（{describe_date(hi['date_start'], hi['date_end'])}）不再相交，"
             f"{o['conflict_label']}随之消除；其余条件不变"),
            [{"op": "update_rule", "rule_id": lo["id"],
              "fields": {"date_start": ds, "date_end": de}}],
            [lo["id"]],
        ))

    # 时段维度：余量须能表达为单条规则窗口
    cuts = [tuple(seg) for seg in o["intersection"]["time_segments"]]
    remainder = TimeDomain(tuple(_subtract_segments(list(lo["time"].segments), cuts)))
    if remainder.segments and remainder != lo["time"]:
        window = _domain_to_window(remainder)
        if window is not None:
            out.append(_base_suggestion(
                o, "narrow_lower_time",
                f"收窄 #{lo['id']}「{lo['name']}」的每日时段为 {describe_time(remainder)}",
                (f"#{lo['id']} 的时段由「{describe_time(lo['time'])}」收窄为"
                 f"「{describe_time(remainder)}」，与 #{hi['id']} 的时段"
                 f"（{describe_time(hi['time'])}）不再相交，{o['conflict_label']}随之消除；"
                 "其余条件不变"),
                [{"op": "update_rule", "rule_id": lo["id"],
                  "fields": {"time_start": window[0], "time_end": window[1]}}],
                [lo["id"]],
            ))
    return out


# ---------------------------------------------------------------------------
# 建议生成（含确定性预演）
# ---------------------------------------------------------------------------

def apply_ops_to_rows(rule_rows: Sequence[dict], ops: Sequence[dict]) -> list[dict]:
    """在规则行副本上应用操作（纯函数，用于预演与期望状态计算）。"""
    out = [dict(r) for r in rule_rows]
    by_id = {int(r["id"]): r for r in out}
    for op in ops:
        target = by_id.get(int(op["rule_id"]))
        if target is None:
            continue
        if op["op"] == "update_rule":
            target.update(op["fields"])
        elif op["op"] == "disable_rule":
            target["enabled"] = 0
    return out


def _suggestion_id(s: dict) -> str:
    payload = {"kind": s["kind"], "rule_ids": s["rule_ids"], "ops": s["ops"]}
    digest = hashlib.sha1(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return f"sug_{digest[:12]}"


def generate_suggestions(rule_rows: Sequence[dict]) -> list[dict]:
    """基于当前规则集合生成确定性修复建议（含预演）。

    入参为全部规则行（dict 序列，含停用规则）；返回按规则 id 稳定排序的
    建议列表。同一规则集在任何时刻得到完全相同的建议（含建议 id）。
    """
    audit = audit_rules(rule_rows)
    if not audit["overlaps"]:
        return []
    norm = {r["id"]: r for r in (_norm_rule(r) for r in rule_rows)}
    raw = {int(r["id"]): dict(r) for r in rule_rows}

    suggestions: list[dict] = []
    for o in audit["overlaps"]:
        ctype = o["conflict_type"]
        if ctype not in FIXABLE_TYPES:
            continue
        hi = norm[o["higher_rule_id"]]
        lo = norm[o["lower_rule_id"]]
        if ctype == "shadowed":
            suggestions.append(_disable_suggestion(o, hi, lo))
        elif ctype == "redundant_overlap":
            merge = _merge_suggestion(o, hi, lo)
            if merge is not None:
                suggestions.append(merge)
            suggestions.extend(_narrow_suggestions(o, hi, lo))
        else:  # action_conflict
            suggestions.extend(_narrow_suggestions(o, hi, lo))
            suggestions.append(_disable_suggestion(o, hi, lo))

    # 不同关系可能生成效果完全相同的建议（如两组冲突都指向"停用 #5"）：
    # 按操作内容去重，保留排序最靠前的一条（其预演会覆盖全部被解决的关系）
    suggestions.sort(key=lambda s: (min(s["rule_ids"]), max(s["rule_ids"]),
                                    _KIND_ORDER[s["kind"]]))
    seen_ops: set[str] = set()
    unique: list[dict] = []
    for s in suggestions:
        sig = json.dumps(s["ops"], sort_keys=True, ensure_ascii=False)
        if sig in seen_ops:
            continue
        seen_ops.add(sig)
        unique.append(s)

    for s in unique:
        s["id"] = _suggestion_id(s)
    unique.sort(key=lambda s: (min(s["rule_ids"]), max(s["rule_ids"]),
                               _KIND_ORDER[s["kind"]], s["id"]))

    # 确定性预演：模拟应用后重新审计，输出解决/新增的关系
    for s in unique:
        simulated = apply_ops_to_rows(list(raw.values()), s["ops"])
        diff = audit_diff(audit, audit_rules(simulated))
        s["preview"] = {
            "resolved": [brief_relation(x) for x in diff["resolved"]],
            "introduced": [brief_relation(x) for x in diff["introduced"]],
            "resolved_count": diff["resolved_count"],
            "introduced_count": diff["introduced_count"],
        }
    return unique


def check_compatible(selected: Sequence[dict]) -> Optional[str]:
    """校验所选建议两两不冲突（影响规则集互不相交）；返回错误信息或 None。"""
    owner: dict[int, str] = {}
    for s in selected:
        for rid in s["affected_rule_ids"]:
            if rid in owner:
                return (
                    f"所选建议相互冲突：规则 #{rid} 同时被"
                    f"「{owner[rid]}」与「{s['title']}」影响，请二选一"
                )
            owner[rid] = s["title"]
    return None
