/* 冷链告警抑制策略沙盒 —— 原生前端逻辑 */
"use strict";

const $ = (sel) => document.querySelector(sel);
const api = async (path, opts = {}) => {
  const res = await fetch(path, {
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `请求失败 HTTP ${res.status}`);
  return data;
};

let state = {
  staged: [],
  alerts: [],
  rules: [],
  runs: [],
  settings: {},
  compare: { a: null, b: null, result: null },
  events: { events: [], devices: [], gap_seconds: 900 },
  snapshots: [],
  snapCompare: { from: null, to: null, result: null },
  audit: { result: null, filterRuleId: null },
  fix: { data: null, selected: new Set(), lastResult: null },
};

function eventFilters() {
  return {
    device: $("#ev-filter-device")?.value || "",
    level: $("#ev-filter-level")?.value || "",
    status: $("#ev-filter-status")?.value || "",
    start: $("#ev-filter-start")?.value || "",
    end: $("#ev-filter-end")?.value || "",
  };
}

// ---------------------------------------------------------------------------
// 通用 UI
// ---------------------------------------------------------------------------

let toastTimer = null;
function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = "toast"), 3200);
}
const fail = (e) => toast(e.message || String(e), true);

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function levelBadge(level) {
  const l = (level || "info").toLowerCase();
  return `<span class="level level-${l}">${esc(l)}</span>`;
}

function levelCell(level) {
  return level ? levelBadge(level) : '<span class="badge">全部 *</span>';
}

// ---------------------------------------------------------------------------
// 数据加载
// ---------------------------------------------------------------------------

async function refreshAll() {
  await Promise.all([loadStaged(), loadAlerts(), loadRules(), loadRuns(), loadSettings()]);
  renderStaged();
  renderAlerts();
  renderRules();
  renderRunSelects();
  renderSettings();
  if (state.compare.a && state.compare.b) await loadCompare();
  await loadEvents();
  await loadSnapshots();
}

async function loadStaged() {
  state.staged = await api("/api/staged");
}
async function loadAlerts() {
  state.alerts = await api("/api/alerts");
}
async function loadRules() {
  state.rules = await api("/api/rules");
}
async function loadRuns() {
  state.runs = await api("/api/runs");
}
async function loadSettings() {
  state.settings = await api("/api/settings");
}

// ---------------------------------------------------------------------------
// Tab 1: 告警注入
// ---------------------------------------------------------------------------

function renderStaged() {
  $("#staged-count").textContent = state.staged.length;
  const box = $("#staged-list");
  if (!state.staged.length) {
    box.innerHTML = '<p class="empty">队列为空，可在右侧导入 JSON 或填充内置示例</p>';
    return;
  }
  box.innerHTML = state.staged.map((item, i) => {
    const p = item.payload;
    return `<div class="staged-item">
      <span class="seq">${i + 1}</span>
      <div class="body">
        <div class="meta">${esc(p.ts || "(无 ts，用注入时刻)")} · ${esc(p.device_id || "-")} ·
          ${esc(p.batch_id || "-")} · ${levelBadge(p.level)} · ${esc(p.alert_type || "-")}</div>
        <div class="msg">${esc(p.message || "")}</div>
      </div>
      <button class="btn ghost small" data-del-staged="${item.id}">移除</button>
    </div>`;
  }).join("");
}

function renderCandidates(cands) {
  if (!cands || !cands.length) return "";
  const items = cands.map((c) => {
    const checks = (c.checks || []).map((t) => {
      const miss = t.includes("不匹配") || t.includes("不命中") || t.includes("早于") || t.includes("晚于");
      return `<li class="${miss ? "check-miss" : "check-hit"}">${esc(t)}</li>`;
    }).join("");
    return `<div class="candidate ${c.matched ? "winner" : ""}">
      <div class="cand-head">#${c.rule_id} ${esc(c.name)} · 优先级 ${c.priority} ·
        动作 ${c.action === "pass" ? "放行" : "抑制"} ${c.matched ? "— <b>匹配</b>" : "— 未匹配"}</div>
      <ul class="checks">${checks}</ul>
    </div>`;
  }).join("");
  return `<div class="candidates"><div style="color:var(--accent)">规则评估过程（按优先级）：</div>${items}</div>`;
}

function renderAlerts() {
  const rows = state.alerts;
  const tbody = $("#alerts-body");
  let passN = 0, suppressN = 0;
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">尚未注入告警</td></tr>';
  } else {
    tbody.innerHTML = rows.map(({ alert, decision }) => {
      if (decision) {
        if (decision.decision === "pass") passN++; else suppressN++;
      }
      const d = decision
        ? `<span class="decision ${decision.decision}">${decision.decision === "pass" ? "放行 PASS" : "抑制 SUPPRESS"}</span>`
        : '<span class="badge">未评估</span>';
      const rule = decision
        ? `<div class="reason-cell">
             <div class="reason-text">${decision.rule_id ? `命中规则 #${decision.rule_id}「${esc(decision.rule_name)}」` : "无命中规则（默认策略）"}</div>
             <div style="color:var(--muted);margin-top:2px">${esc(decision.reason)}</div>
             <div style="color:var(--muted);margin-top:2px;font-size:11.5px">冷却指纹: <code>${esc(decision.fingerprint)}</code></div>
             ${renderCandidates(decision.candidates)}
           </div>`
        : '<span class="empty">-</span>';
      return `<tr>
        <td>${alert.seq}</td>
        <td>${esc(alert.ts)}</td>
        <td>${esc(alert.device_id || "-")}</td>
        <td>${esc(alert.batch_id || "-")}</td>
        <td>${levelBadge(alert.level)}</td>
        <td>${esc(alert.alert_type || "-")}</td>
        <td style="max-width:220px">${esc(alert.message || "")}</td>
        <td>${d}</td>
        <td>${rule}</td>
      </tr>`;
    }).join("");
  }
  $("#live-pass").textContent = `${passN} 放行`;
  $("#live-suppress").textContent = `${suppressN} 抑制`;
}

async function doInject(next) {
  try {
    if (next) await api("/api/alerts/inject-next", { method: "POST" });
    else await api("/api/alerts/inject-all", { method: "POST" });
    await refreshAll();
    await loadReceiverLogs();
    toast(next ? "已注入队首 1 条" : "队列已全部顺序注入");
  } catch (e) { fail(e); }
}

async function doUndo() {
  if (!state.alerts.length) return toast("没有可撤销的注入", true);
  const last = state.alerts[state.alerts.length - 1].alert;
  if (!confirm(`撤销最近注入 #${last.seq}（${last.device_id} / ${last.alert_type}）？\n该告警会退回队列头部，其在所有评估中的决定与投递日志一并删除。`)) return;
  try {
    await api("/api/alerts/undo", { method: "POST" });
    await refreshAll();
    await loadReceiverLogs();
    toast("已撤销最近注入");
  } catch (e) { fail(e); }
}

function readJsonTextarea(el) {
  const text = el.value.trim();
  if (!text) throw new Error("JSON 内容为空");
  try { return JSON.parse(text); }
  catch { throw new Error("JSON 解析失败，请检查格式"); }
}

async function doImport(append) {
  let data;
  try { data = readJsonTextarea($("#import-json")); } catch (e) { return fail(e); }
  const body = Array.isArray(data) ? { alerts: data, append } : { ...data, append: append || data.append };
  try {
    const r = await api("/api/alerts/import", { method: "POST", body: JSON.stringify(body) });
    await refreshAll();
    toast(`已${r.appended ? "追加" : "导入"} ${r.imported} 条告警到队列`);
  } catch (e) { fail(e); }
}

async function doDirectInject() {
  let data;
  try { data = readJsonTextarea($("#direct-json")); } catch (e) { return fail(e); }
  if (Array.isArray(data)) return fail("该入口仅接受单条 JSON 对象，批量导入请使用左侧");
  try {
    await api("/api/alerts/inject", { method: "POST", body: JSON.stringify(data) });
    await refreshAll();
    await loadReceiverLogs();
    toast("单条告警已注入并完成评估");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 2: 事件关联
// ---------------------------------------------------------------------------

function fmtDuration(seconds) {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.round(seconds / 60);
  if (m < 60) return `${m} 分钟`;
  const h = Math.floor(m / 60), rest = m % 60;
  return rest ? `${h} 小时 ${rest} 分` : `${h} 小时`;
}

async function loadEvents() {
  const params = new URLSearchParams();
  const f = eventFilters();
  for (const [k, v] of Object.entries(f)) {
    if (v) params.set(k, v);
  }
  const qs = params.toString();
  state.events = await api(`/api/events${qs ? `?${qs}` : ""}`);
  renderEvents();
}

function renderEventDeviceOptions() {
  const sel = $("#ev-filter-device");
  const current = sel.value;
  sel.innerHTML = '<option value="">全部设备</option>' +
    state.events.devices.map((d) =>
      `<option value="${esc(d)}">${esc(d || "(空设备)")}</option>`).join("");
  if (state.events.devices.includes(current)) sel.value = current;
}

function renderEvents() {
  const data = state.events;
  const gapInput = $("#ev-gap");
  if (!gapInput.value) gapInput.value = data.gap_seconds;
  $("#ev-gap-saved").textContent = `当前间隔 ${data.gap_seconds}s（${fmtDuration(data.gap_seconds)}）`;
  $("#ev-total").textContent = `${data.total} 事件`;
  $("#ev-acked").textContent = `${data.acknowledged_count} 已确认`;
  $("#ev-unacked").textContent = `${data.unacknowledged_count} 未确认`;
  renderEventDeviceOptions();

  const box = $("#events-list");
  if (!data.events.length) {
    box.innerHTML = '<p class="empty">没有匹配的事件。先到「告警注入」页注入告警，或调整筛选条件。</p>';
    return;
  }
  box.innerHTML = data.events.map((ev) => {
    const dur = (new Date(ev.last_ts) - new Date(ev.first_ts)) / 1000;
    const seqs = ev.member_seqs.map((s) => `<span class="seq-chip">#${s}</span>`).join(" ");
    const ack = ev.acknowledged
      ? '<span class="badge pass">✓ 已确认</span>'
      : '<span class="badge suppress">● 未确认</span>';
    const timeline = ev.members.map((m) => {
      const a = m.alert;
      const dec = m.live_decision === "pass"
        ? '<span class="decision pass small">live 放行</span>'
        : m.live_decision === "suppress"
          ? '<span class="decision suppress small">live 抑制</span>'
          : '<span class="badge">无 live 决定</span>';
      return `<li class="tl-item">
        <span class="tl-dot level-dot-${esc(a.level)}"></span>
        <span class="tl-seq">#${a.seq}</span>
        <span class="tl-ts">${esc(a.ts)}</span>
        ${levelBadge(a.level)}
        <span class="tl-msg">${esc(a.message || "")}</span>
        ${dec}
      </li>`;
    }).join("");
    return `<div class="event-card${ev.acknowledged ? " is-ack" : ""}">
      <div class="ev-head">
        <div class="ev-title">
          <b>${esc(ev.device_id || "(空设备)")}</b>
          <span class="badge">${esc(ev.alert_type || "(无类型)")}</span>
          ${levelBadge(ev.max_level)}<span class="hint" style="margin:0">最高级别</span>
          ${ack}
          ${ev.acked_at ? `<span class="hint" style="margin:0">确认于 ${esc(ev.acked_at)}</span>` : ""}
        </div>
        <div class="ev-actions">
          <button class="btn small" data-toggle-ev="${ev.id}" data-ack="${ev.acknowledged ? 0 : 1}">
            ${ev.acknowledged ? "取消确认" : "✓ 确认事件"}
          </button>
        </div>
      </div>
      <div class="ev-meta">
        <span>首条 <b>${esc(ev.first_ts)}</b></span>
        <span>末条 <b>${esc(ev.last_ts)}</b></span>
        <span>跨度 ${fmtDuration(dur)}</span>
        <span>告警数 <b>${ev.alert_count}</b></span>
        <span>聚合间隔 ${ev.gap_seconds}s</span>
      </div>
      <div class="ev-seqs">成员序号：${seqs}</div>
      <details class="ev-timeline">
        <summary>事件时间线（${ev.alert_count} 条，按告警时间排序）</summary>
        <ul class="tl-list">${timeline}</ul>
      </details>
    </div>`;
  }).join("");
}

async function saveGap() {
  const value = Number($("#ev-gap").value);
  try {
    const r = await api("/api/correlation/config", {
      method: "PUT", body: JSON.stringify({ gap_seconds: value }),
    });
    await loadEvents();
    const s = r.recompute;
    toast(`间隔已更新为 ${r.gap_seconds}s：新建 ${s.created} / 更新 ${s.updated} / 删除 ${s.deleted} 个事件`);
  } catch (e) { fail(e); }
}

async function recomputeEvents() {
  try {
    const s = await api("/api/events/recompute", { method: "POST" });
    await loadEvents();
    toast(`重算完成：共 ${s.events} 个事件（新建 ${s.created} / 更新 ${s.updated} / 删除 ${s.deleted}）`);
  } catch (e) { fail(e); }
}

async function toggleEventAck(id, ack) {
  try {
    await api(`/api/events/${id}/ack`, {
      method: "POST", body: JSON.stringify({ acknowledged: !!ack }),
    });
    await loadEvents();
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 2.5: 事件演进（快照 + 血缘对比）
// ---------------------------------------------------------------------------

const KIND_LABEL = {
  added: "新增",
  removed: "消失",
  continued: "延续",
  ack_changed: "确认变化",
  split: "拆分",
  merge: "合并",
  split_merge: "拆分+合并",
};

async function loadSnapshots() {
  state.snapshots = await api("/api/event-snapshots");
  renderSnapshots();
  renderSnapSelects();
}

function snapLabel(s) {
  const note = s.note ? ` · ${s.note}` : "";
  return `#${s.id} ${s.created_at} · ${s.event_count} 事件 · ${s.acknowledged_count} 已确认 · 间隔 ${s.gap_seconds}s${note}`;
}

function renderSnapshots() {
  $("#snap-total").textContent = `${state.snapshots.length} 个快照`;
  const box = $("#snapshot-list");
  if (!state.snapshots.length) {
    box.innerHTML = '<p class="empty">暂无快照。先注入告警生成事件，再点击上方按钮保存第一份快照。</p>';
    return;
  }
  box.innerHTML = state.snapshots.map((s) => `
    <div class="snapshot-item">
      <span><b>#${s.id}</b> ${esc(s.note || "(无说明)")}</span>
      <span style="color:var(--muted)">${esc(s.created_at)} · ${s.event_count} 事件 ·
        ${s.acknowledged_count} 已确认 · 间隔 ${s.gap_seconds}s</span>
    </div>`).join("");
}

function renderSnapSelects() {
  const from = $("#snap-from"), to = $("#snap-to");
  const opts = state.snapshots.map((s) =>
    `<option value="${s.id}">${esc(snapLabel(s))}</option>`).join("");
  from.innerHTML = opts;
  to.innerHTML = opts;
  const ids = state.snapshots.map((s) => s.id);
  // 默认对比最近两份快照；保留用户已选（若仍存在）
  if (!state.snapCompare.from || !ids.includes(state.snapCompare.from)) {
    state.snapCompare.from = ids.length >= 2 ? ids[ids.length - 2] : (ids[0] || null);
  }
  if (!state.snapCompare.to || !ids.includes(state.snapCompare.to)) {
    state.snapCompare.to = ids.length ? ids[ids.length - 1] : null;
  }
  if (state.snapCompare.from) from.value = state.snapCompare.from;
  if (state.snapCompare.to) to.value = state.snapCompare.to;
}

async function createSnapshot() {
  try {
    const s = await api("/api/event-snapshots", {
      method: "POST",
      body: JSON.stringify({ note: $("#snap-note").value.trim() }),
    });
    $("#snap-note").value = "";
    await loadSnapshots();
    toast(`快照 #${s.id} 已保存：${s.event_count} 个事件（间隔 ${s.gap_seconds}s），此后不再被改写`);
  } catch (e) { fail(e); }
}

async function compareSnapshots() {
  const from = Number($("#snap-from").value);
  const to = Number($("#snap-to").value);
  if (!from || !to) return toast("需要至少保存两份快照才能对比", true);
  state.snapCompare.from = from;
  state.snapCompare.to = to;
  try {
    state.snapCompare.result =
      await api(`/api/event-snapshots/compare?from_id=${from}&to_id=${to}`);
    renderSnapCompare();
  } catch (e) { fail(e); }
}

function snapEventHtml(ev) {
  const seqs = ev.member_seqs.map((s) => `<span class="seq-chip">#${s}</span>`).join(" ");
  const ack = ev.acknowledged
    ? '<span class="badge pass">✓ 已确认</span>'
    : '<span class="badge suppress">● 未确认</span>';
  return `<div class="rel-ev">
    <div class="rel-ev-head">
      <b>${esc(ev.device_id || "(空设备)")}</b>
      <span class="badge">${esc(ev.alert_type || "(无类型)")}</span>
      ${levelBadge(ev.max_level)} ${ack}
      <span class="hint" style="margin:0">事件ID ${ev.event_id}</span>
    </div>
    <div class="ev-meta">
      <span>首条 <b>${esc(ev.first_ts)}</b></span>
      <span>末条 <b>${esc(ev.last_ts)}</b></span>
      <span>告警数 <b>${ev.alert_count}</b></span>
    </div>
    <div class="ev-seqs">成员序号：${seqs}</div>
  </div>`;
}

function relationHtml(rel) {
  const badges = [`<span class="rel-kind kind-${rel.kind}">${KIND_LABEL[rel.kind]}</span>`];
  if (!rel.changed) badges.push('<span class="badge">未变化</span>');

  let inter;
  if (rel.old.length === 1 && rel.new.length === 1) {
    inter = `两侧交集 <b>${rel.intersection_count}</b> 条成员`;
  } else if (rel.intersections.length) {
    inter = `总交集 <b>${rel.intersection_count}</b> 条成员（逐对：` +
      rel.intersections.map((x) =>
        `旧E${x.old_event_id}∩新E${x.new_event_id}=${x.count}`).join("，") + "）";
  } else {
    inter = "两侧无交集成员";
  }

  const oldSide = rel.old.map(snapEventHtml).join("") ||
    '<p class="empty" style="padding:10px">（旧快照中无对应事件）</p>';
  const newSide = rel.new.map(snapEventHtml).join("") ||
    '<p class="empty" style="padding:10px">（新快照中无对应事件）</p>';
  return `<div class="relation-card${rel.changed ? "" : " unchanged"}">
    <div class="rel-head">${badges.join("")}<span class="rel-inter">${inter}</span></div>
    <div class="rel-sides">
      <div class="rel-side">
        <div class="rel-side-title">旧快照侧（${rel.old.length} 个事件）</div>${oldSide}
      </div>
      <div class="rel-arrow">→</div>
      <div class="rel-side">
        <div class="rel-side-title">新快照侧（${rel.new.length} 个事件）</div>${newSide}
      </div>
    </div>
  </div>`;
}

function renderSnapCompare() {
  const r = state.snapCompare.result;
  if (!r) return;
  const s = r.summary;
  $("#snap-summary").innerHTML =
    `对比 <b>#${r.from.id}${r.from.note ? ` ${esc(r.from.note)}` : ""}</b>（${esc(r.from.created_at)}）→
     <b>#${r.to.id}${r.to.note ? ` ${esc(r.to.note)}` : ""}</b>（${esc(r.to.created_at)}）：
     共 ${s.relations} 组血缘关系 — 新增 ${s.added} · 消失 ${s.removed} ·
     拆分 ${s.split} · 合并 ${s.merge} · 延续 ${s.continued} ·
     确认变化 ${s.ack_changed} · 未变化 ${s.unchanged}`;

  const onlyChanged = $("#snap-only-changed").checked;
  const rels = r.relations.filter((rel) => !onlyChanged || rel.changed);
  $("#snap-relations").innerHTML = rels.length
    ? rels.map(relationHtml).join("")
    : `<p class="empty">${onlyChanged ? "两个快照之间没有任何变化" : "两个快照都没有事件"}</p>`;
}

// ---------------------------------------------------------------------------
// Tab 3: 规则
// ---------------------------------------------------------------------------

function ruleMatches(r) {
  const dev = r.match_device || "*", batch = r.match_batch || "*", lvl = r.match_level || "*";
  const time = r.time_start ? `${r.time_start}-${r.time_end}` : "全天";
  const dates = (r.date_start || r.date_end)
    ? `${r.date_start || "…"} ~ ${r.date_end || "…"}` : "不限";
  return { dev, batch, lvl, time, dates };
}

function renderRules() {
  const tbody = $("#rules-body");
  if (!state.rules.length) {
    tbody.innerHTML = '<tr><td colspan="12" class="empty">暂无规则（无匹配时全部默认放行）</td></tr>';
    return;
  }
  const enabledOrdered = state.rules.filter((r) => r.enabled);
  const orderMap = new Map(enabledOrdered.map((r, i) => [r.id, i + 1]));
  tbody.innerHTML = state.rules.map((r) => {
    const m = ruleMatches(r);
    const order = r.enabled ? (orderMap.get(r.id) || "-") : "—";
    return `<tr${r.enabled ? "" : ' style="opacity:0.45"'}>
      <td>${order}</td>
      <td><b>${esc(r.name)}</b><br><span style="color:var(--muted);font-size:11.5px">${esc(r.description || "")}</span></td>
      <td>${r.action === "pass"
        ? '<span class="decision pass">pass</span>'
        : '<span class="decision suppress">suppress</span>'}</td>
      <td>${r.priority}</td>
      <td>${r.cooldown_seconds || "-"}</td>
      <td>${esc(m.dev)}</td>
      <td>${esc(m.batch)}</td>
      <td>${levelCell(m.lvl === "*" ? "" : m.lvl)}</td>
      <td>${esc(m.time)}</td>
      <td>${esc(m.dates)}</td>
      <td>${r.enabled ? '<span class="badge pass">启用</span>' : '<span class="badge suppress">停用</span>'}</td>
      <td style="white-space:nowrap">
        <button class="btn small" data-edit-rule="${r.id}">编辑</button>
        <button class="btn small" data-toggle-rule="${r.id}">${r.enabled ? "停用" : "启用"}</button>
        <button class="btn small danger" data-del-rule="${r.id}">删除</button>
      </td>
    </tr>`;
  }).join("");
}

function fillRuleForm(r) {
  $("#rule-id").value = r ? r.id : "";
  $("#form-title").textContent = r ? `编辑规则 #${r.id}` : "新建抑制规则";
  $("#f-name").value = r ? r.name : "";
  $("#f-desc").value = r ? r.description : "";
  $("#f-action").value = r ? r.action : "suppress";
  $("#f-priority").value = r ? r.priority : 100;
  $("#f-cooldown").value = r ? r.cooldown_seconds : 0;
  $("#f-device").value = r ? r.match_device : "";
  $("#f-batch").value = r ? r.match_batch : "";
  $("#f-level").value = r ? r.match_level : "";
  $("#f-time-start").value = r ? r.time_start : "";
  $("#f-time-end").value = r ? r.time_end : "";
  $("#f-date-start").value = r ? r.date_start : "";
  $("#f-date-end").value = r ? r.date_end : "";
  $("#f-enabled").checked = r ? !!r.enabled : true;
}

function collectRuleForm() {
  return {
    name: $("#f-name").value,
    description: $("#f-desc").value,
    action: $("#f-action").value,
    priority: Number($("#f-priority").value),
    cooldown_seconds: Number($("#f-cooldown").value),
    match_device: $("#f-device").value.trim(),
    match_batch: $("#f-batch").value.trim(),
    match_level: $("#f-level").value,
    time_start: $("#f-time-start").value.trim(),
    time_end: $("#f-time-end").value.trim(),
    date_start: $("#f-date-start").value,
    date_end: $("#f-date-end").value,
    enabled: $("#f-enabled").checked,
  };
}

async function saveRule() {
  const id = $("#rule-id").value;
  const body = collectRuleForm();
  try {
    await api(id ? `/api/rules/${id}` : "/api/rules", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(body),
    });
    fillRuleForm(null);
    await loadRules();
    renderRules();
    await refreshAuditIfLoaded();
    await refreshFixIfLoaded();
    toast(id ? "规则已更新（提示：可到「策略对比」生成回放查看影响）" : "规则已创建");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 3.5: 规则审计（可达条件覆盖分析，只读）
// ---------------------------------------------------------------------------

function renderAuditFilterOptions() {
  const sel = $("#audit-filter-rule");
  if (!sel) return;
  const rules = state.audit.result?.rules || [];
  sel.innerHTML = '<option value="">全部规则</option>' +
    rules.map((r) => `<option value="${r.id}">#${r.id} ${esc(r.name)}</option>`).join("");
  if (state.audit.filterRuleId) sel.value = String(state.audit.filterRuleId);
}

async function loadAudit() {
  const qs = state.audit.filterRuleId ? `?rule_id=${state.audit.filterRuleId}` : "";
  try {
    state.audit.result = await api(`/api/rule-audit${qs}`);
  } catch (e) {
    // 筛选中的规则刚被删除：回退到全部规则再试一次
    if (state.audit.filterRuleId) {
      state.audit.filterRuleId = null;
      state.audit.result = await api("/api/rule-audit");
      const sel = $("#audit-filter-rule");
      if (sel) sel.value = "";
    } else {
      throw e;
    }
  }
  renderAudit();
}

function auditRuleBadges(r) {
  const badges = [
    r.action === "pass"
      ? '<span class="decision pass">pass</span>'
      : '<span class="decision suppress">suppress</span>',
    `<span class="badge">优先级 ${r.priority}</span>`,
  ];
  if (r.cooldown_seconds) badges.push(`<span class="badge">冷却 ${r.cooldown_seconds}s</span>`);
  return badges.join(" ");
}

function renderAuditRules() {
  const tbody = $("#audit-rules-body");
  const rules = state.audit.result?.rules || [];
  if (!rules.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">没有启用规则（全部停用时审计无对象）</td></tr>';
    return;
  }
  tbody.innerHTML = rules.map((r) => {
    const shadow = r.fully_shadowed
      ? `<span class="badge suppress">⛨ 死规则：被 #${r.shadowed_by.join("、#")} 完全遮蔽</span>`
      : '<span class="badge pass">可达</span>';
    return `<tr class="${r.fully_shadowed ? "row-dead" : ""}">
      <td>#${r.id}</td>
      <td><b>${esc(r.name)}</b><br><span style="color:var(--muted);font-size:11.5px">${esc(r.description || "")}</span></td>
      <td>${r.action === "pass"
        ? '<span class="decision pass">pass</span>'
        : '<span class="decision suppress">suppress</span>'}</td>
      <td>${r.priority}</td>
      <td>${r.cooldown_seconds || "-"}</td>
      <td style="font-size:12px;color:var(--muted)">${esc(r.conditions.reach_summary)}</td>
      <td style="white-space:nowrap">${shadow}</td>
    </tr>`;
  }).join("");
}

function auditRuleBox(r, side, o) {
  const dead = side === "lower" && o.fully_shadowed;
  const title = side === "higher"
    ? `高优先级（评估时先匹配，${o.may_change_outcome ? "交集内由它决定结果" : "交集内先命中"}）`
    : dead
      ? "低优先级（可达域被完全包含，永远不会命中）"
      : "低优先级（仅交集部分被覆盖）";
  return `<div class="audit-rule-box is-${side}${dead ? " is-dead" : ""}">
    <div class="top">
      <b>#${r.id} ${esc(r.name)}</b>
      ${auditRuleBadges(r)}
    </div>
    <div class="conds">${esc(r.conditions.reach_summary)}</div>
    <div class="conds">${esc(title)}</div>
  </div>`;
}

function renderAuditOverlaps() {
  const res = state.audit.result;
  const box = $("#audit-overlaps");
  const overlaps = res?.overlaps || [];
  if (!overlaps.length) {
    box.innerHTML = '<p class="empty">没有可达条件相交的规则对——任意两条启用规则之间都不会互相覆盖。</p>';
    return;
  }
  box.innerHTML = overlaps.map((o) => {
    const hi = o.higher_rule, lo = o.lower_rule;
    const flags = [`<span class="audit-kind kind-${o.conflict_type}">${o.conflict_label}</span>`];
    if (o.fully_shadowed) flags.push('<span class="badge suppress">⛨ 完全遮蔽</span>');
    if (o.may_change_outcome) flags.push('<span class="badge suppress">可能改变结果</span>');
    return `<div class="audit-card kind-${o.conflict_type}">
      <div class="audit-head">
        ${flags.join("")}
        <span class="audit-rule-ids">规则 <b>#${hi.id}</b>（优先级 ${hi.priority}）
          覆盖 <b>#${lo.id}</b>（优先级 ${lo.priority}）</span>
      </div>
      <div class="audit-inter">交集可达条件：<b>${esc(o.intersection.summary)}</b></div>
      <p class="audit-detail">${esc(o.detail)}</p>
      <div class="audit-side-title">涉及规则</div>
      <div class="audit-sides">
        ${auditRuleBox(hi, "higher", o)}
        <div class="audit-side-arrow">覆盖 →</div>
        ${auditRuleBox(lo, "lower", o)}
      </div>
    </div>`;
  }).join("");
}

function renderAudit() {
  const res = state.audit.result;
  if (!res) return;
  const t = res.totals;
  $("#audit-enabled-count").textContent = `${res.enabled_rule_count} 条启用规则`;
  $("#audit-conflict-count").textContent = `${t.may_change_outcome} 组可能改变结果`;
  $("#audit-shadow-count").textContent = `${t.fully_shadowed_rules.length} 条被完全遮蔽`;
  $("#audit-filter-note").textContent = res.filter_note ||
    (res.filter_rule_id ? `已筛选：只显示涉及 #${res.filter_rule_id} 的关系（共 ${res.overlaps_filtered} / ${t.overlaps} 组）` : "");
  $("#audit-summary").innerHTML =
    `共审计 <b>${res.pair_count}</b> 对启用规则，存在可达交集 <b>${t.overlaps}</b> 组：
     动作冲突 <b style="color:var(--red)">${t.action_conflict}</b> ·
     冷却差异 <b style="color:#c084fc">${t.cooldown_conflict}</b> ·
     完全遮蔽 <b style="color:var(--red)">${t.shadowed}</b> ·
     冗余重叠 <b>${t.redundant_overlap}</b>；
     其中 <b>${t.fully_shadowed_relations}</b> 组为完全包含，
     被遮蔽规则：<b>${t.fully_shadowed_rules.length ? "#" + t.fully_shadowed_rules.join("、#") : "无"}</b>。
     结论只取决于当前启用规则集，与告警数据及 live/replay 历史无关。`;
  renderAuditFilterOptions();
  renderAuditRules();
  renderAuditOverlaps();
}

// ---------------------------------------------------------------------------
// Tab 3.6: 修复工作台（确定性建议、单事务应用、最近一次修复撤销）
// ---------------------------------------------------------------------------

async function loadFixes() {
  state.fix.data = await api("/api/rule-audit/fixes");
  // 规则变更后建议会重新生成：丢弃已失效的勾选
  const valid = new Set(state.fix.data.suggestions.map((s) => s.id));
  state.fix.selected = new Set([...state.fix.selected].filter((id) => valid.has(id)));
  renderFixes();
}

function fixRelPair(r) {
  const [a, b] = r.rule_ids;
  return `#${Math.min(a, b)} ↔ #${Math.max(a, b)}`;
}

function fixRelList(items, empty) {
  if (!items.length) return `<li>${empty}</li>`;
  return items.map((r) => `<li>${fixRelPair(r)}（${esc(r.conflict_label)}）</li>`).join("");
}

function fixSuggestionHtml(s) {
  const checked = state.fix.selected.has(s.id) ? "checked" : "";
  const resolved = s.preview.resolved_count
    ? `<span class="badge pass">✓ 解决 ${s.preview.resolved_count} 组</span>` : "";
  const introduced = s.preview.introduced_count
    ? `<span class="badge suppress">⚠ 新增 ${s.preview.introduced_count} 组</span>` : "";
  return `<div class="fix-card kind-${s.conflict_type}">
    <label class="fix-check"><input type="checkbox" data-fix-select="${s.id}" ${checked}></label>
    <div class="fix-body">
      <div class="fix-head">
        <span class="fix-kind kind-${s.kind}">${s.kind_label}</span>
        <span class="audit-kind kind-${s.conflict_type}">${s.conflict_label}</span>
        <b>${esc(s.title)}</b>
      </div>
      <div class="fix-detail">${esc(s.detail)}</div>
      <div class="fix-meta">
        <span>影响规则 ${s.affected_rule_ids.map((id) => `<span class="seq-chip">#${id}</span>`).join(" ")}</span>
        <span>针对关系 ${fixRelPair({ rule_ids: s.rule_ids })}</span>
        ${resolved}${introduced}
      </div>
      <details class="fix-preview">
        <summary>确定性预演（单独应用该建议后的审计变化）</summary>
        <div class="fix-preview-grid">
          <div><b>解决的关系</b><ul>${fixRelList(s.preview.resolved, "无")}</ul></div>
          <div><b>新增的关系</b><ul>${fixRelList(s.preview.introduced, "无")}</ul></div>
        </div>
      </details>
    </div>
  </div>`;
}

function fixHistoryHtml(f) {
  const stateBadge = f.undone
    ? `<span class="badge">已撤销${f.undone_at ? ` · ${esc(f.undone_at)}` : ""}</span>`
    : '<span class="badge pass">已应用</span>';
  const kinds = f.suggestions.map((s) =>
    `<span class="fix-kind kind-${s.kind}">${esc(s.kind_label)}</span>`).join(" ");
  return `<div class="snapshot-item" style="display:block">
    <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">
      <span><b>#${f.id}</b> ${esc(f.summary)}</span>
      <span>${stateBadge}</span>
    </div>
    <div style="color:var(--muted);margin-top:4px">
      ${esc(f.created_at)} · ${kinds} · 影响规则 ${f.affected_rule_ids.map((id) => `#${id}`).join("、")}
      · 关系 ${f.diff.before_total} → ${f.diff.after_total}
      （解决 ${f.diff.resolved_count}${f.diff.introduced_count ? ` · 新增 ${f.diff.introduced_count}` : ""}）
    </div>
  </div>`;
}

function updateFixButtons() {
  $("#btn-fix-apply").disabled = !state.fix.selected.size;
  $("#btn-fix-apply").textContent = state.fix.selected.size
    ? `✅ 应用选中的 ${state.fix.selected.size} 条建议` : "✅ 应用选中的建议";
  const undoId = state.fix.data?.latest_undoable_id;
  $("#btn-fix-undo").disabled = !undoId;
  $("#btn-fix-undo").textContent = undoId ? `↩ 撤销最近一次修复 (#${undoId})` : "↩ 撤销最近一次修复";
}

function renderFixes() {
  const d = state.fix.data;
  if (!d) return;
  const t = d.audit_totals;
  $("#fix-sug-count").textContent = `${d.suggestions.length} 条待处理建议`;
  $("#fix-relation-count").textContent = `${t.overlaps} 组审计关系`;
  $("#fix-undo-state").textContent = d.latest_undoable_id
    ? `可撤销修复 #${d.latest_undoable_id}` : "无可撤销修复";
  $("#fix-summary").innerHTML =
    `当前 <b>${d.enabled_rule_count}</b> 条启用规则存在 <b>${t.overlaps}</b> 组审计关系
     （动作冲突 ${t.action_conflict} · 完全遮蔽 ${t.shadowed} · 冗余重叠 ${t.redundant_overlap} ·
     冷却差异 ${t.cooldown_conflict}），其中可自动修复的关系已生成
     <b>${d.suggestions.length}</b> 条建议。`;

  const box = $("#fix-suggestions");
  box.innerHTML = d.suggestions.length
    ? d.suggestions.map(fixSuggestionHtml).join("")
    : '<p class="empty">没有待处理建议——当前启用规则之间不存在可自动修复的审计关系。</p>';

  $("#fix-history-count").textContent = `${d.fixes.length} 条记录`;
  $("#fix-history").innerHTML = d.fixes.length
    ? d.fixes.map(fixHistoryHtml).join("")
    : '<p class="empty">暂无修复记录。勾选建议并应用后，这里会展示每次修复的前后关系变化。</p>';
  updateFixButtons();
}

function renderFixResult() {
  const r = state.fix.lastResult;
  if (!r) return;
  $("#fix-result-card").hidden = false;
  const d = r.diff;
  const relRow = (o, mark) => `<tr>
    <td>${mark}</td><td>#${Math.min(...o.rule_ids)} ↔ #${Math.max(...o.rule_ids)}</td>
    <td><span class="audit-kind kind-${o.conflict_type}">${o.conflict_label}</span></td>
    <td style="color:var(--muted);font-size:12px">${esc(o.intersection.summary)}</td>
  </tr>`;
  $("#fix-result").innerHTML =
    `<p class="hint" style="margin-bottom:8px">修复 <b>#${r.fix_id}</b>（${esc(r.summary)}）已在同一事务中应用：
     审计关系 <b>${d.before_total}</b> → <b>${d.after_total}</b> 组，
     解决 <b style="color:var(--green)">${d.resolved_count}</b> 组，
     新增 <b style="color:${d.introduced_count ? "var(--red)" : "var(--green)"}">${d.introduced_count}</b> 组，
     仍存在 ${d.remaining_count} 组。</p>
     <div class="table-wrap"><table>
       <thead><tr><th>变化</th><th>规则对</th><th>类型</th><th>交集可达条件</th></tr></thead>
       <tbody>
         ${d.resolved.map((o) => relRow(o, '<span class="badge pass">✓ 已解决</span>')).join("")}
         ${d.introduced.map((o) => relRow(o, '<span class="badge suppress">⚠ 新增</span>')).join("")}
       </tbody>
     </table></div>`;
}

async function applyFixes() {
  const ids = [...state.fix.selected];
  if (!ids.length) return toast("请先勾选要应用的建议", true);
  if (!confirm(`在同一事务中应用 ${ids.length} 条建议？\n任一校验失败（建议失效/相互冲突/结果校验不通过）都会自动回滚。`)) return;
  try {
    const r = await api("/api/rule-audit/fixes/apply", {
      method: "POST", body: JSON.stringify({ suggestion_ids: ids }),
    });
    state.fix.lastResult = r;
    state.fix.selected = new Set();
    await loadFixes();
    await loadRules(); renderRules();
    await refreshAuditIfLoaded();
    renderFixResult();
    toast(`修复 #${r.fix_id} 已应用：关系 ${r.diff.before_total} → ${r.diff.after_total} 组` +
      (r.diff.introduced_count ? `（新增 ${r.diff.introduced_count} 组）` : ""));
  } catch (e) {
    fail(e);
    await loadFixes().catch(() => {});
  }
}

async function undoFix() {
  const id = state.fix.data?.latest_undoable_id;
  if (!id) return;
  if (!confirm(`撤销最近一次修复 #${id}？\n受影响规则将恢复到修复前状态（撤销前会校验修复后未被手动修改）。`)) return;
  try {
    const r = await api(`/api/rule-audit/fixes/${id}/undo`, { method: "POST" });
    await loadFixes();
    await loadRules(); renderRules();
    await refreshAuditIfLoaded();
    toast(`修复 #${id} 已撤销，规则 ${r.restored_rule_ids.map((x) => `#${x}`).join("、")} 已恢复`);
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// Tab 4: 策略对比
// ---------------------------------------------------------------------------

function runLabel(r) {
  return `#${r.id} ${r.kind === "live" ? "[实时链]" : "[回放]"} ${r.note || ""} (${r.created_at}) — ${r.pass_count}放/${r.suppress_count}抑`;
}

function renderRunSelects() {
  const a = $("#cmp-a"), b = $("#cmp-b");
  const opts = state.runs.map((r) => `<option value="${r.id}">${esc(runLabel(r))}</option>`).join("");
  a.innerHTML = opts;
  b.innerHTML = opts;
  const live = state.runs.find((r) => r.kind === "live");
  const latestReplay = [...state.runs].reverse().find((r) => r.kind === "replay");
  state.compare.a = state.compare.a || (latestReplay ? latestReplay.id : live ? live.id : null);
  state.compare.b = state.compare.b || (live ? live.id : null);
  if (state.compare.a && state.runs.some((r) => r.id === state.compare.a)) a.value = state.compare.a;
  if (state.compare.b && state.runs.some((r) => r.id === state.compare.b)) b.value = state.compare.b;
  renderSnapshot();
}

async function doReplay() {
  try {
    const r = await api("/api/replays", {
      method: "POST",
      body: JSON.stringify({ note: $("#replay-note").value || "策略变更后回放" }),
    });
    $("#replay-note").value = "";
    await loadRuns();
    renderRunSelects();
    state.compare.a = r.id;
    $("#cmp-a").value = r.id;
    await loadCompare();
    toast(`已生成回放 #${r.id}，重放 ${r.replayed_alerts} 条告警`);
  } catch (e) { fail(e); }
}

async function loadCompare() {
  const a = Number($("#cmp-a").value);
  const b = Number($("#cmp-b").value);
  state.compare.a = a; state.compare.b = b;
  try {
    const result = await api(`/api/compare?run_a=${a}&run_b=${b}`);
    state.compare.result = result;
    renderCompare();
    renderSnapshot();
  } catch (e) { fail(e); }
}

function decisionCell(d) {
  if (!d) return '<span class="badge">无记录</span>';
  return `<span class="decision ${d.decision}">${d.decision === "pass" ? "放行" : "抑制"}</span>
          <div style="color:var(--muted);margin-top:3px;font-size:11.5px">
            ${d.rule_id ? `#${d.rule_id} ${esc(d.rule_name)}` : "默认策略"}</div>`;
}

function renderCompare() {
  const res = state.compare.result;
  if (!res) return;
  $("#cmp-summary").innerHTML =
    `对比 <b>${esc(res.run_a.note || res.run_a.kind)} (#${res.run_a.id})</b> 与
     <b>${esc(res.run_b.note || res.run_b.kind)} (#${res.run_b.id})</b><br>
     共 ${res.total} 条告警，<b style="color:var(--amber)">${res.changed_count} 条决定发生变化</b>`;
  $("#compare-body").innerHTML = res.rows.map((row) => {
    const a = row.alert;
    return `<tr class="${row.changed ? "row-changed" : ""}">
      <td>${a.seq}</td>
      <td>${esc(a.device_id || "-")}<br><span style="color:var(--muted)">${esc(a.batch_id || "-")}</span></td>
      <td>${levelBadge(a.level)}<br><span style="color:var(--muted)">${esc(a.alert_type || "-")}</span></td>
      <td style="white-space:nowrap">${esc(a.ts)}</td>
      <td>${decisionCell(row.a)}</td>
      <td class="reason-cell" style="max-width:280px;color:var(--muted);font-size:12px">${esc(row.a ? row.a.reason : "-")}</td>
      <td>${decisionCell(row.b)}</td>
      <td class="reason-cell" style="max-width:280px;color:var(--muted);font-size:12px">${esc(row.b ? row.b.reason : "-")}</td>
      <td>${row.changed
        ? '<span class="diff-mark">⇄ 已变化</span>'
        : '<span class="no-diff">一致</span>'}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="9" class="empty">暂无已注入告警</td></tr>';
}

function renderSnapshot() {
  const a = state.runs.find((r) => r.id === Number($("#cmp-a")?.value));
  if (!a) return;
  $("#cmp-snapshot").innerHTML = (a.rule_snapshot || []).map((r) => {
    const m = ruleMatches(r);
    return `<div class="snap-rule">
      <div class="top">
        <b>#${r.id} ${esc(r.name)}</b>
        ${r.action === "pass" ? '<span class="decision pass">pass</span>' : '<span class="decision suppress">suppress</span>'}
        <span class="badge">优先级 ${r.priority}</span>
        ${r.cooldown_seconds ? `<span class="badge">冷却 ${r.cooldown_seconds}s</span>` : ""}
      </div>
      <div class="conds">设备 ${esc(m.dev)} · 批次 ${esc(m.batch)} · 级别 ${esc(m.lvl)} · 时段 ${esc(m.time)} · 日期 ${esc(m.dates)}</div>
    </div>`;
  }).join("") || '<p class="empty">无规则</p>';
}

// ---------------------------------------------------------------------------
// Tab 5: 模拟接收端
// ---------------------------------------------------------------------------

function renderSettings() {
  $("#set-forward").checked = state.settings.forward_enabled === "true";
  $("#set-mode").value = state.settings.receiver_mode || "mock";
  $("#set-url").value = state.settings.external_url || "";
}

async function saveSettings() {
  const body = {
    forward_enabled: $("#set-forward").checked,
    receiver_mode: $("#set-mode").value,
    external_url: $("#set-url").value.trim(),
  };
  try {
    state.settings = await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
    renderSettings();
    toast("设置已保存");
  } catch (e) { fail(e); }
}

async function loadReceiverLogs() {
  const logs = await api("/api/receiver/logs?limit=100");
  const box = $("#receiver-logs");
  if (!logs.length) {
    box.innerHTML = '<p class="empty">暂无投递记录。开启自动转发后注入放行告警，或手动发送测试包。</p>';
    return;
  }
  box.innerHTML = logs.map((l) => `
    <div class="log-item">
      <div class="top">
        <span><span class="status-${esc(l.status)}">● ${esc(l.status)}</span>
          ${l.alert_seq ? ` · 告警 #${l.alert_seq}` : ""} · ${esc(l.target)}</span>
        <span style="color:var(--muted)">${esc(l.created_at)}</span>
      </div>
      <div style="color:var(--muted);font-size:12px;margin-top:3px">${esc(l.detail)}</div>
      <pre>${esc(JSON.stringify(l.payload, null, 2))}</pre>
    </div>`).join("");
}

async function testMock() {
  try {
    await api("/mock-webhook", {
      method: "POST",
      body: JSON.stringify({ test: true, source: "sandbox-ui", at: new Date().toISOString() }),
    });
    await loadReceiverLogs();
    toast("测试包已送达内置接收端");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------------------
// 示例数据 & 重置
// ---------------------------------------------------------------------------

const SAMPLE = [
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -15.2℃，高于阈值 -18℃", ts: "2026-09-21T00:05:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "critical", alert_type: "temp_high",
    message: "厢内温度 -9.0℃，存在断链风险", ts: "2026-09-21T00:15:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -16.4℃，夜间抖动", ts: "2026-09-21T00:30:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门开启超过 2 分钟", ts: "2026-09-21T00:45:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门仍未关闭", ts: "2026-09-21T00:47:00" },
  { device_id: "TR-02", batch_id: "B2026-09B", level: "warning", alert_type: "door_open",
    message: "后门仍未关闭（冷却窗内）", ts: "2026-09-21T00:52:00" },
  { device_id: "WH-03", batch_id: "B2026-09C", level: "info", alert_type: "sensor_offline",
    message: "冷库传感器心跳超时", ts: "2026-09-21T01:00:00" },
  { device_id: "TR-01", batch_id: "B2026-09A", level: "warning", alert_type: "temp_high",
    message: "厢内温度 -16.0℃，白天仍偏高（时段窗口外）", ts: "2026-09-21T09:00:00" },
];

// ---------------------------------------------------------------------------
// 事件绑定
// ---------------------------------------------------------------------------

document.addEventListener("click", async (e) => {
  const t = e.target;
  const ds = t.dataset;
  if (ds.toggleEv) {
    await toggleEventAck(Number(ds.toggleEv), Number(ds.ack));
  }
  if (ds.delStaged) {
    try { await api(`/api/staged/${ds.delStaged}`, { method: "DELETE" }); await loadStaged(); renderStaged(); }
    catch (err) { fail(err); }
  }
  if (ds.editRule) {
    const r = state.rules.find((x) => x.id === Number(ds.editRule));
    if (r) { fillRuleForm(r); window.scrollTo({ top: 0, behavior: "smooth" }); }
  }
  if (ds.toggleRule) {
    try {
      await api(`/api/rules/${ds.toggleRule}/toggle`, { method: "POST" });
      await loadRules(); renderRules();
      await refreshAuditIfLoaded();
      await refreshFixIfLoaded();
    }
    catch (err) { fail(err); }
  }
  if (ds.delRule) {
    if (!confirm("确认删除该规则？")) return;
    try {
      await api(`/api/rules/${ds.delRule}`, { method: "DELETE" });
      if (Number($("#rule-id").value) === Number(ds.delRule)) fillRuleForm(null);
      await loadRules(); renderRules();
      await refreshAuditIfLoaded();
      await refreshFixIfLoaded();
    } catch (err) { fail(err); }
  }
});

document.addEventListener("change", (e) => {
  const ds = e.target.dataset || {};
  if (ds.fixSelect) {
    if (e.target.checked) state.fix.selected.add(ds.fixSelect);
    else state.fix.selected.delete(ds.fixSelect);
    updateFixButtons();
  }
});

// 规则变更后若审计页已加载过结果，按当前筛选重新审计（不影响任何 live/replay 数据）
async function refreshAuditIfLoaded() {
  if (state.audit.result) {
    try { await loadAudit(); } catch (err) { fail(err); }
  }
}

// 规则变更后若修复工作台已加载过，重新生成建议并丢弃失效勾选
async function refreshFixIfLoaded() {
  if (state.fix.data) {
    try { await loadFixes(); } catch (err) { fail(err); }
  }
}

function bind() {
  document.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`#tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "receiver") loadReceiverLogs();
    if (btn.dataset.tab === "events") loadEvents().catch(fail);
    if (btn.dataset.tab === "evolution") loadSnapshots().catch(fail);
    if (btn.dataset.tab === "audit") loadAudit().catch(fail);
    if (btn.dataset.tab === "fix") loadFixes().catch(fail);
  }));

  $("#btn-inject-next").addEventListener("click", () => doInject(true));
  $("#btn-inject-all").addEventListener("click", () => doInject(false));
  $("#btn-undo").addEventListener("click", doUndo);
  $("#btn-save-gap").addEventListener("click", saveGap);
  $("#btn-recompute").addEventListener("click", recomputeEvents);
  $("#btn-snapshot").addEventListener("click", createSnapshot);
  $("#btn-compare-snap").addEventListener("click", compareSnapshots);
  $("#snap-only-changed").addEventListener("change", renderSnapCompare);
  $("#btn-clear-filters").addEventListener("click", async () => {
    for (const id of ["#ev-filter-device", "#ev-filter-level", "#ev-filter-status",
                      "#ev-filter-start", "#ev-filter-end"]) {
      $(id).value = "";
    }
    await loadEvents();
  });
  ["#ev-filter-device", "#ev-filter-level", "#ev-filter-status",
   "#ev-filter-start", "#ev-filter-end"].forEach((sel) =>
    $(sel).addEventListener("change", () => loadEvents().catch(fail)));
  $("#btn-import").addEventListener("click", () => doImport(false));
  $("#btn-import-append").addEventListener("click", () => doImport(true));
  $("#btn-direct-inject").addEventListener("click", doDirectInject);
  $("#btn-sample").addEventListener("click", () => {
    $("#import-json").value = JSON.stringify(SAMPLE, null, 2);
    toast("已填充 8 条内置示例，点击「导入（替换队列）」");
  });
  $("#btn-save-rule").addEventListener("click", saveRule);
  $("#btn-cancel-edit").addEventListener("click", () => fillRuleForm(null));
  $("#btn-audit-refresh").addEventListener("click", () => loadAudit().then(() => toast("审计已按当前启用规则重新计算")).catch(fail));
  $("#audit-filter-rule").addEventListener("change", async (e) => {
    state.audit.filterRuleId = e.target.value ? Number(e.target.value) : null;
    try { await loadAudit(); } catch (err) { fail(err); }
  });
  $("#btn-fix-refresh").addEventListener("click", () =>
    loadFixes().then(() => toast("建议已按当前规则重新生成")).catch(fail));
  $("#btn-fix-apply").addEventListener("click", applyFixes);
  $("#btn-fix-undo").addEventListener("click", undoFix);
  $("#btn-replay").addEventListener("click", doReplay);
  $("#cmp-a").addEventListener("change", loadCompare);
  $("#cmp-b").addEventListener("change", loadCompare);
  $("#btn-save-settings").addEventListener("click", saveSettings);
  $("#btn-test-mock").addEventListener("click", testMock);
  $("#btn-clear-logs").addEventListener("click", async () => {
    try { await api("/api/receiver/clear", { method: "POST" }); await loadReceiverLogs(); toast("日志已清空"); }
    catch (err) { fail(err); }
  });
}

bind();
refreshAll().catch(fail);
