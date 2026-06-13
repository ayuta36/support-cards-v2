/* ============================================================
   サポートカード app.js(ローカル高セキュリティ版)
   ------------------------------------------------------------
   ・データはこの端末のブラウザ内のみに保存(外部送信なし)
   ・全データを共有パスコードで暗号化(AES-256-GCM)
   ・総当たり対策:連続失敗で待機時間が伸びる
   ・15分操作がないと自動ロック/バックグラウンドで画面を隠す
   ・チーム制:目的ごとにカードをまとめる
   ・共有:暗号化ファイル(.scard)の書き出し→相手が読み込み

   編集ガイド:
   1. 初期トピック → DEFAULT_TOPICS
   2. 自動ロック時間 → AUTO_LOCK_MIN
   3. 各画面のHTML → ○○Screen 関数
   4. ボタンの動作 → handle()
   ============================================================ */
"use strict";

const APP_VERSION = "1.0.0-local";
const STORE_KEY = "support-card-local-v1";   // 暗号化データの保存先
const META_KEY  = "support-card-meta-v1";    // 試行回数など(非機密)
const AUTO_LOCK_MIN = 15;                     // ★自動ロックまでの分数

// ================= データ定義 =================
const DEFAULT_TOPICS = [
  { id:"emergency", icon:"🚨", title:"発作・緊急時", color:"#E05B4B", desc:"まずこれを見てください", urgent:true },
  { id:"basic", icon:"👤", title:"基本情報", color:"#5B8DB8", desc:"名前・生年月日・連絡先" },
  { id:"communication", icon:"💬", title:"コミュニケーション", color:"#2F8F83", desc:"伝え方・この子のサイン" },
  { id:"meal", icon:"🍽️", title:"食事・水分", color:"#D98E32", desc:"形態・とろみ・禁止のもの" },
  { id:"care", icon:"💊", title:"医療的ケア", color:"#8A6FC8", desc:"薬・吸引・注入など" },
  { id:"posture", icon:"🛏️", title:"姿勢・移動", color:"#4E9A6E", desc:"抱き方・車いす・注意点" },
  { id:"likes", icon:"🌟", title:"好きなこと", color:"#E8A93C", desc:"笑顔になるもの" },
  { id:"dislikes", icon:"😣", title:"苦手なこと", color:"#B06A8C", desc:"避けてほしいこと" },
];

const SAMPLE_TEAM = {
  id:"team_sample", name:"やまだ家", emoji:"🏠", color:"#2F8F83",
  people:[{
    id:"sample", name:"はなちゃん", emoji:"🌸", photo:null, note:"いつもニコニコ、音楽が大すき",
    topicDefs: structuredClone(DEFAULT_TOPICS),
    topics:{
      emergency:[
        {label:"発作のサイン", value:"目が右上を向いて、体がかたくなります"},
        {label:"対応", value:"横向きに寝かせて、時間を計ってください。5分以上続いたら救急車を呼んでください"},
      ],
      basic:[
        {label:"名前", value:"山田 はな(やまだ はな)"},
        {label:"生年月日", value:"2018年4月10日(7歳)"},
        {label:"緊急連絡先", value:"母:090-XXXX-XXXX"},
      ],
      communication:[
        {label:"うれしいとき", value:"手をパタパタさせて、高い声を出します"},
        {label:"話しかけ方", value:"左側からゆっくり、名前を呼んでから話してください"},
      ],
      likes:[{label:"音楽", value:"オルゴールの音、童謡「ちょうちょ」"}],
    },
  }],
};

const EMOJIS = ["🌸","🌻","🐻","🐰","🚂","⭐","🍀","🎈","🐬","🦁"];
const TEAM_EMOJIS = ["🏠","🏫","🎪","🏥","🚌","⛺","🎨","🎵","🌈","🤝"];
const TOPIC_ICONS = ["📌","😴","🚽","🏫","🎒","🧸","🩺","🦷","👂","👀","🧴","🌡️","🎵","✋","❤️","📝"];
const TOPIC_COLORS = ["#5B8DB8","#E05B4B","#2F8F83","#D98E32","#8A6FC8","#4E9A6E","#E8A93C","#B06A8C","#7A8AA0","#C2724E"];
const TEAM_COLORS = ["#2F8F83","#D9707E","#4E8FB8","#E8A93C","#8A6FC8","#4E9A6E"];

// ================= 小さな道具 =================
const uid = () => Math.random().toString(36).slice(2,9);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtDate = (iso)=>{ try{ return new Date(iso).toLocaleString("ja-JP",{month:"numeric",day:"numeric",hour:"2-digit",minute:"2-digit"}); }catch(e){ return iso; } };

function shade(hex, pct){
  const n = parseInt(hex.slice(1),16);
  const f = (c)=> Math.max(0,Math.min(255, Math.round(pct<0 ? c*(1+pct/100) : c+(255-c)*pct/100)));
  const r=f((n>>16)&255), g=f((n>>8)&255), b=f(n&255);
  return "#"+((1<<24)+(r<<16)+(g<<8)+b).toString(16).slice(1);
}
const grad = (c)=>`linear-gradient(145deg, ${shade(c,10)}, ${shade(c,-16)})`;

// ================= 暗号化 =================
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
async function deriveKey(passcode, salt){
  const mat = await crypto.subtle.importKey("raw", new TextEncoder().encode(passcode), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations:310000, hash:"SHA-256" },
    mat, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
}
async function encryptJson(obj, key){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv:b64(iv), data:b64(ct) };
}
async function decryptJson(payload, key){
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(payload.iv)}, key, unb64(payload.data));
  return JSON.parse(new TextDecoder().decode(pt));
}

// ================= 状態 =================
let stage = "boot";   // boot | setup-pass | locked | home | passcode? | ready
let cryptoKey = null, salt = null;
let teams = [];
let view = { teamId:null, screen:"list", personId:null, topicId:null, editing:false, organize:false };
let draft = [], modal = null, modalDraft = null;
let toastTimer = null, screenError = "", lockWaitMsg = "";
let idleTimer = null;

// 試行制限(非機密メタ)
function loadMeta(){ try{ return JSON.parse(localStorage.getItem(META_KEY)) || {}; }catch(e){ return {}; } }
function saveMeta(m){ try{ localStorage.setItem(META_KEY, JSON.stringify(m)); }catch(e){} }

// ---- 表示設定 ----
const PREFS_KEY = "support-card-prefs-v1";
const THEMES = [
  { id:"milk", label:"ミルク", color:"#2F8F83" },
  { id:"sakura", label:"さくら", color:"#D9707E" },
  { id:"sora", label:"そら", color:"#4E8FB8" },
  { id:"wakaba", label:"わかば", color:"#4E9A6E" },
];
let prefs = { fs:"m", theme:"milk" };
function loadPrefs(){ try{ const r = localStorage.getItem(PREFS_KEY); if(r) prefs = {...prefs, ...JSON.parse(r)}; }catch(e){} }
function applyPrefs(){
  document.body.dataset.fs = prefs.fs;
  document.body.dataset.theme = prefs.theme;
  try{ localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); }catch(e){}
}

// ---- 読み上げ ----
let speaking = false;
function stopSpeak(){ if(speaking){ speechSynthesis.cancel(); speaking = false; } }
function speakTopic(p, t){
  if(!("speechSynthesis" in window)){ alert("この端末のブラウザは読み上げに対応していません"); return; }
  const entries = p.topics[t.id]||[];
  const text = [ `${p.name}の、${t.title}`, ...entries.map(e => (e.label ? e.label + "。" : "") + e.value) ].join("。");
  const u = new SpeechSynthesisUtterance(text);
  u.lang = "ja-JP"; u.rate = 0.95;
  u.onend = ()=>{ speaking = false; render(); };
  u.onerror = ()=>{ speaking = false; render(); };
  speechSynthesis.cancel(); speechSynthesis.speak(u); speaking = true;
}

// ================= セキュリティ:自動ロック・覗き見ガード =================
function lockNow(){
  stopSpeak();
  cryptoKey = null; teams = [];
  view = { teamId:null, screen:"list", personId:null, topicId:null, editing:false, organize:false };
  modal = null; modalDraft = null;
  clearTimeout(idleTimer);
  stage = "locked"; screenError = ""; render();
}
function resetIdle(){
  clearTimeout(idleTimer);
  if(stage==="home" || stage==="ready"){
    idleTimer = setTimeout(lockNow, AUTO_LOCK_MIN*60*1000);
  }
}
["click","keydown","touchstart","mousemove"].forEach(ev=>
  document.addEventListener(ev, resetIdle, {passive:true}));
// バックグラウンドに回ったら画面を隠す+ロック
document.addEventListener("visibilitychange", ()=>{
  if(document.hidden){
    document.body.classList.add("peek-guard");
    if(stage==="home"||stage==="ready") lockNow();
  }else{
    document.body.classList.remove("peek-guard");
  }
});

// ================= 保存・読み込み =================
async function persist(){
  const enc = await encryptJson({teams}, cryptoKey);
  localStorage.setItem(STORE_KEY, JSON.stringify({ v:1, salt:b64(salt), iv:enc.iv, data:enc.data, savedAt:new Date().toISOString() }));
}
async function save(){
  try{
    await persist();
    const t = document.getElementById("toast");
    t.classList.add("show"); clearTimeout(toastTimer);
    toastTimer = setTimeout(()=>t.classList.remove("show"), 1600);
  }catch(e){ alert("保存に失敗しました。写真が多すぎる場合は減らしてください。"); }
}
function normalizeTeam(t){
  return { ...t, color:t.color||"#2F8F83", emoji:t.emoji||"🏠",
    people:(t.people||[]).map(p=>({...p, topicDefs:p.topicDefs||structuredClone(DEFAULT_TOPICS), topics:p.topics||{}})) };
}

// ================= 解錠・新規設定 =================
const LOCKOUTS = [0,0,0,5,15,30,60]; // 失敗回数→待機秒。7回目以降は60秒
function tryReason(){
  const m = loadMeta();
  if(m.lockUntil && Date.now() < m.lockUntil){
    return Math.ceil((m.lockUntil - Date.now())/1000);
  }
  return 0;
}
async function unlock(passcode){
  const wait = tryReason();
  if(wait>0){ lockWaitMsg = `しばらく待ってください(あと${wait}秒)`; render(); return; }
  try{
    const stored = JSON.parse(localStorage.getItem(STORE_KEY));
    salt = unb64(stored.salt);
    cryptoKey = await deriveKey(passcode, salt);
    const obj = await decryptJson(stored, cryptoKey);
    teams = (obj.teams||[]).map(normalizeTeam);
    saveMeta({fails:0});
    lockWaitMsg = ""; screenError = "";
    stage = "home"; resetIdle(); render();
  }catch(e){
    cryptoKey = null;
    const m = loadMeta();
    const fails = (m.fails||0) + 1;
    const wsec = LOCKOUTS[Math.min(fails, LOCKOUTS.length-1)];
    const meta = { fails };
    if(wsec>0) meta.lockUntil = Date.now() + wsec*1000;
    saveMeta(meta);
    screenError = "パスコードがちがいます";
    lockWaitMsg = wsec>0 ? `${fails}回まちがえました。${wsec}秒待ってからお試しください` : "";
    if(wsec>0){
      setTimeout(()=>{ lockWaitMsg=""; render(); }, wsec*1000);
    }
    render();
  }
}
async function setupNew(passcode){
  salt = crypto.getRandomValues(new Uint8Array(16));
  cryptoKey = await deriveKey(passcode, salt);
  teams = [normalizeTeam(structuredClone(SAMPLE_TEAM))];
  // 旧ローカル版(暗号化なし)からの引き継ぎ
  try{
    const old = JSON.parse(localStorage.getItem("support-card-data-v2")||"null");
    if(old && !old.enc && Array.isArray(old.people) && old.people.length){
      teams = [normalizeTeam({ id:uid(), name:"わたしの家族", emoji:"🏠", color:"#2F8F83", people:old.people })];
    }
  }catch(e){}
  await persist();
  saveMeta({fails:0});
  stage = "home"; resetIdle(); render();
}

// ================= 共通パーツ =================
const getTeam = () => teams.find(t=>t.id===view.teamId);
const getPerson = () => getTeam()?.people.find(p=>p.id===view.personId);
const getTopic = (p) => p?.topicDefs.find(t=>t.id===view.topicId);

function avatarHtml(p, size){
  if(p.photo) return `<span class="avatar photo" style="width:${size}px;height:${size}px"><img src="${p.photo}" alt=""></span>`;
  return `<span class="avatar" style="width:${size}px;height:${size}px;font-size:${size*0.5}px">${esc(p.emoji||"🌸")}</span>`;
}
function readPhoto(file){
  return new Promise((resolve,reject)=>{
    const img = new Image(); const url = URL.createObjectURL(file);
    img.onload = ()=>{
      const max=300, sc=Math.min(1, max/Math.max(img.width,img.height));
      const c=document.createElement("canvas");
      c.width=Math.round(img.width*sc); c.height=Math.round(img.height*sc);
      c.getContext("2d").drawImage(img,0,0,c.width,c.height);
      URL.revokeObjectURL(url); resolve(c.toDataURL("image/jpeg",0.82));
    };
    img.onerror = reject; img.src = url;
  });
}

// ================= 描画 =================
const app = document.getElementById("app");
function render(){
  let html = "";
  if(stage==="boot") html = `<div class="lock-wrap"><div class="spinner">読み込み中…</div></div>`;
  else if(stage==="setup-pass") html = setupScreen();
  else if(stage==="locked") html = lockScreen();
  else if(stage==="home") html = homeScreen();
  else{
    const tm=getTeam(), p=getPerson();
    if(view.screen==="detail" && p && getTopic(p)) html = detailScreen(p, getTopic(p));
    else if(view.screen==="person" && p) html = personScreen(p);
    else html = listScreen(tm);
  }
  app.innerHTML = `<div class="screen">${html}</div>` + (modal ? modalHtml() : "");
  bindEvents();
  const f = document.getElementById("lk-pass") || document.getElementById("su-pass1");
  if(f) f.focus();
  window.scrollTo(0,0);
}

// ---- 初回パスコード設定 ----
function setupScreen(){
  return `
  <div class="lock-wrap">
    <div class="lock-card">
      <div class="login-logo">🌸</div>
      <div class="lock-title">ようこそ</div>
      <div class="lock-sub">はじめに、このアプリを守る<b>パスコード</b>を決めましょう。<br>データはこのパスコードで暗号化されます。</div>
      <input class="lock-input" id="su-pass1" type="password" autocomplete="new-password" placeholder="パスコード(4文字以上)">
      <input class="lock-input" id="su-pass2" type="password" autocomplete="new-password" placeholder="もう一度入力">
      <div class="lock-error">${esc(screenError)}</div>
      <button class="big-btn" style="width:100%;background:var(--teal);color:#fff" data-act="setup-go">はじめる</button>
      <div class="login-note">⚠️ パスコードを忘れるとデータを復元できません。<br>必ず控えてください。</div>
    </div>
  </div>`;
}

// ---- ロック画面 ----
function lockScreen(){
  return `
  <div class="lock-wrap">
    <div class="lock-card">
      <div class="login-logo">🔒</div>
      <div class="lock-title">サポートカード</div>
      <div class="lock-sub">パスコードを入力してください。</div>
      <input class="lock-input" id="lk-pass" type="password" autocomplete="off" placeholder="パスコード">
      <div class="lock-error">${esc(screenError)}</div>
      <div class="lock-wait">${esc(lockWaitMsg)}</div>
      <button class="big-btn" style="width:100%;background:var(--teal);color:#fff" data-act="unlock">ひらく</button>
    </div>
  </div>`;
}

// ---- ホーム:チーム一覧 ----
function homeScreen(){
  return `
  <div class="list-head">
    <div class="brand">サポートカード</div>
    <h1 class="list-title">ホーム</h1>
    <p class="greet">🌸 「家族」「学校」「イベント」など、伝える相手ごとにチームを作れます。</p>
    <div class="toolbar">
      <button class="tool-btn" data-act="settings">⚙️ 設定</button>
      <button class="tool-btn" data-act="lock-manual">🔒 ロックする</button>
      <button class="tool-btn" data-act="open-about">ℹ️ について</button>
    </div>
  </div>
  <div class="list-body" style="grid-template-columns:1fr">
    ${teams.length===0?`<div class="empty"><span style="font-size:40px;display:block;margin-bottom:8px">🏡</span>まだチームがありません。<br>まずは「家族」チームを作ってみましょう!</div>`:""}
    ${teams.map(t=>`
      <button class="team-card" style="--accent:${esc(t.color)}" data-act="enter-team" data-id="${t.id}">
        <span class="team-emoji">${esc(t.emoji)}</span>
        <span>
          <span class="team-name" style="display:block">${esc(t.name)}</span>
          <span class="team-sub" style="display:block">👤 ${t.people.length}人のカード</span>
        </span>
        <span class="chev">›</span>
      </button>`).join("")}
    <button class="add-card" data-act="open-team-create"><span style="font-size:26px">+</span> 新しいチームを作る</button>
  </div>`;
}

// ---- チーム内:カード一覧 ----
function listScreen(tm){
  if(!tm){ stage="home"; return homeScreen(); }
  return `
  <div class="list-head">
    <button class="back-link" data-act="back-home">← ホーム(チーム一覧)</button>
    <h1 class="list-title">${esc(tm.emoji)} ${esc(tm.name)}</h1>
    <p class="list-sub">カードをタップすると、その子のことがわかります</p>
    <div class="toolbar">
      <button class="tool-btn" data-act="share-team">📤 このチームを共有</button>
      <button class="tool-btn" data-act="import">📥 読み込み</button>
      <button class="tool-btn" data-act="edit-team">✏️ チーム編集</button>
      <button class="tool-btn" data-act="settings">⚙️ 設定</button>
    </div>
  </div>
  <div class="list-body">
    ${tm.people.length===0?`<div class="empty"><span style="font-size:40px;display:block;margin-bottom:8px">🌱</span>まだカードがありません。<br>「新しいカードを作る」から始めましょう。</div>`:""}
    ${tm.people.map(p=>`
      <button class="person-card" data-act="open-person" data-id="${p.id}">
        ${avatarHtml(p,64)}
        <span>
          <span class="hero-name" style="display:block">${esc(p.name)}</span>
          ${p.note?`<span class="hero-note" style="display:block">${esc(p.note)}</span>`:""}
        </span>
        <span class="chev">›</span>
      </button>`).join("")}
    <button class="add-card" data-act="add-person"><span style="font-size:26px">+</span> 新しいカードを作る</button>
  </div>`;
}

function personScreen(p){
  const tm=getTeam();
  return `
  <div class="p-head">
    <button class="back-link" data-act="back-list">← ${esc(tm.name)} の一覧</button>
    <button class="hero" data-act="edit-person">
      ${avatarHtml(p,68)}
      <span>
        <span class="hero-name" style="display:block">${esc(p.name)}</span>
        ${p.note?`<span class="hero-note" style="display:block">${esc(p.note)}</span>`:""}
        <span class="hero-hint" style="display:block">タップして名前・写真を編集 ✏️</span>
      </span>
    </button>
    <div class="toolbar">
      <button class="tool-btn" data-act="toggle-organize">${view.organize?"✅ 整理を終わる":"🔧 トピックを整理"}</button>
      <button class="tool-btn" data-act="print">🖨 印刷・PDF</button>
      ${teams.length>1?`<button class="tool-btn" data-act="open-copyto">📋 他のチームへコピー</button>`:""}
    </div>
  </div>
  <div class="grid">
    ${p.topicDefs.map((t,i)=>{
      const n = (p.topics[t.id]||[]).length;
      return `
      <button class="tile ${t.urgent?"urgent":""}" style="background:${grad(t.color)}" data-act="open-topic" data-id="${t.id}">
        ${view.organize?`
        <span class="tile-tools">
          ${i>0?`<span class="tile-tool" tabindex="0" data-act="move-up" data-id="${t.id}" role="button" aria-label="上へ">↑</span>`:""}
          ${i<p.topicDefs.length-1?`<span class="tile-tool" tabindex="0" data-act="move-down" data-id="${t.id}" role="button" aria-label="下へ">↓</span>`:""}
          <span class="tile-tool" tabindex="0" data-act="del-topic" data-id="${t.id}" role="button" aria-label="削除" style="color:#C0584B">🗑</span>
        </span>`
        : (n>0?`<span class="tile-badge">${n}件</span>`:"")}
        <span class="tile-icon">${esc(t.icon)}</span>
        <span class="tile-title">${esc(t.title)}</span>
        <span class="tile-desc">${n>0?esc(t.desc||"記入ずみ"):"まだ未記入"}</span>
      </button>`;
    }).join("")}
    <button class="add-tile" data-act="add-topic"><span style="font-size:28px">+</span><span style="font-size:14px;font-weight:900">トピックを追加</span></button>
  </div>
  <div class="footer-hint">知りたいことをタップすると、必要な情報だけが大きく表示されます</div>`;
}

function detailScreen(p, t){
  const entries = p.topics[t.id]||[];
  let body;
  if(!view.editing){
    body = `
      ${entries.length===0?`<div class="empty">まだ何も書かれていません。<br>「書きこむ」から追加できます。</div>`:""}
      ${entries.map(e=>`
        <div class="entry" style="border-left:5px solid ${t.color}">
          ${e.label?`<div class="entry-label" style="color:${t.color}">${esc(e.label)}</div>`:""}
          <div class="entry-value">${esc(e.value)}</div>
        </div>`).join("")}
      <button class="big-btn" style="background:var(--card);color:${t.color};border:2px solid ${t.color}" data-act="start-edit">✏️ 書きこむ</button>`;
  }else{
    body = `
      ${draft.map((d,i)=>`
        <div class="edit-card">
          <input class="input" placeholder="見出し(例:対応のしかた)" value="${esc(d.label)}" data-draft-label="${i}">
          <textarea class="textarea" rows="3" placeholder="内容を書いてください" data-draft-value="${i}">${esc(d.value)}</textarea>
          <button class="remove-link" data-act="draft-remove" data-i="${i}">この項目を消す</button>
        </div>`).join("")}
      <button class="big-btn" style="background:var(--card);color:var(--sub);border:2px dashed var(--line)" data-act="draft-add">+ 項目をふやす</button>
      <div class="btn-row">
        <button class="big-btn" style="flex:1;background:var(--line);color:var(--sub)" data-act="cancel-edit">やめる</button>
        <button class="big-btn" style="flex:2;background:${t.color};color:#fff" data-act="save-edit">保存する</button>
      </div>`;
  }
  return `
  <div class="d-head" style="background:${grad(t.color)}">
    <div style="display:flex;justify-content:space-between;gap:10px">
      <button class="d-back" data-act="back-person">← もどる</button>
      ${entries.length?`<button class="d-back" data-act="speak">${speaking?"⏹ 止める":"♪ 読み上げ"}</button>`:""}
    </div>
    <div class="d-row">
      <span style="font-size:40px">${esc(t.icon)}</span>
      <div>
        <div class="d-person">${esc(p.emoji||"")} ${esc(p.name)}</div>
        <h1 class="d-title">${esc(t.title)}</h1>
      </div>
    </div>
  </div>
  <div class="d-body">${body}</div>`;
}

// ---- モーダル ----
function modalHtml(){
  const d = modalDraft;
  if(modal==="person"){
    return `
    <div class="overlay" data-act="close-modal"><div class="modal" data-stop>
      <h2>${d.isNew?"新しいカードを作る":"カードを編集"}</h2>
      <div style="display:flex;align-items:center;gap:14px;margin-bottom:8px">
        ${avatarHtml(d,72)}
        <div style="display:flex;flex-direction:column;gap:6px">
          <button class="photo-btn" data-act="pick-photo">📷 写真を選ぶ</button>
          ${d.photo?`<button class="photo-btn" style="color:var(--danger)" data-act="clear-photo">写真を消す</button>`:""}
        </div>
      </div>
      <div class="m-label">名前</div>
      <input class="input" id="m-name" placeholder="例:はなちゃん" value="${esc(d.name)}">
      ${!d.photo?`<div class="m-label">写真のかわりのマーク</div><div class="pick-row">
        ${EMOJIS.map(em=>`<button class="emoji-btn ${d.emoji===em?"on":""}" data-act="pick-emoji" data-v="${em}">${em}</button>`).join("")}</div>`:""}
      <div class="m-label">ひとこと紹介</div>
      <input class="input" id="m-note" placeholder="例:音楽がだいすき" value="${esc(d.note)}">
      <div class="btn-row">
        <button class="big-btn" style="flex:1;background:var(--line);color:var(--sub)" data-act="close-modal">やめる</button>
        <button class="big-btn" style="flex:2;background:var(--teal);color:#fff" data-act="save-person">保存する</button>
      </div>
      ${!d.isNew?`<button class="danger-link" data-act="del-person">このカードを削除する</button>`:""}
    </div></div>`;
  }
  if(modal==="team"){
    const editing = !d.isNew;
    return `
    <div class="overlay" data-act="close-modal"><div class="modal" data-stop>
      <h2>${editing?"チームを編集":"新しいチームを作る"}</h2>
      <div class="m-label">チーム名</div>
      <input class="input" id="t-name" placeholder="例:やまだ家、○○小学校、夏のキャンプ" value="${esc(d.name)}">
      <div class="m-label">マーク</div>
      <div class="pick-row">${TEAM_EMOJIS.map(em=>`<button class="emoji-btn ${d.emoji===em?"on":""}" data-act="pick-team-emoji" data-v="${em}">${em}</button>`).join("")}</div>
      <div class="m-label">テーマ色</div>
      <div class="pick-row">${TEAM_COLORS.map(c=>`<button class="color-btn ${d.color===c?"on":""}" style="background:${c}" data-act="pick-team-color" data-v="${c}" aria-label="色"></button>`).join("")}</div>
      <div class="lock-error" id="t-err"></div>
      <div class="btn-row">
        <button class="big-btn" style="flex:1;background:var(--line);color:var(--sub)" data-act="close-modal">やめる</button>
        <button class="big-btn" style="flex:2;background:${d.color};color:#fff" data-act="${editing?"save-team-edit":"create-team"}">${editing?"保存":"作る"}</button>
      </div>
      ${editing && teams.length>1?`<button class="danger-link" data-act="del-team">このチームを削除する</button>`:""}
    </div></div>`;
  }
  if(modal==="copyto"){
    const tm=getTeam();
    return `
    <div class="overlay" data-act="close-modal"><div class="modal" data-stop>
      <h2>📋 他のチームへコピー</h2>
      <p style="font-size:12.5px;color:var(--sub);line-height:1.7;margin-bottom:12px">コピー先を選んでください。コピー後は独立したカードになります。</p>
      ${teams.filter(t=>t.id!==tm.id).map(t=>`
        <button class="team-card" style="--accent:${esc(t.color)};margin-bottom:10px" data-act="copy-card" data-id="${t.id}">
          <span class="team-emoji" style="width:44px;height:44px;font-size:24px">${esc(t.emoji)}</span>
          <span class="team-name" style="font-size:16px">${esc(t.name)}</span><span class="chev">›</span>
        </button>`).join("")}
      <div class="btn-row"><button class="big-btn" style="flex:1;background:var(--line);color:var(--sub)" data-act="close-modal">やめる</button></div>
    </div></div>`;
  }
  if(modal==="topic"){
    return `
    <div class="overlay" data-act="close-modal"><div class="modal" data-stop>
      <h2>新しいトピック</h2>
      <div class="m-label">トピック名</div>
      <input class="input" id="m-topic-title" placeholder="例:睡眠、学校でのようす" value="${esc(d.title)}">
      <div class="m-label">アイコン</div>
      <div class="pick-row">${TOPIC_ICONS.map(ic=>`<button class="emoji-btn ${d.icon===ic?"on":""}" data-act="pick-icon" data-v="${ic}">${ic}</button>`).join("")}</div>
      <div class="m-label">色</div>
      <div class="pick-row">${TOPIC_COLORS.map(c=>`<button class="color-btn ${d.color===c?"on":""}" style="background:${c}" data-act="pick-color" data-v="${c}" aria-label="色"></button>`).join("")}</div>
      <div class="btn-row">
        <button class="big-btn" style="flex:1;background:var(--line);color:var(--sub)" data-act="close-modal">やめる</button>
        <button class="big-btn" style="flex:2;background:${d.color};color:#fff" data-act="save-topic">追加する</button>
      </div>
    </div></div>`;
  }
  if(modal==="settings"){
    const inTeam = stage==="ready";
    return `
    <div class="overlay" data-act="close-modal"><div class="modal" data-stop>
      <h2>⚙️ 設定</h2>
      <div class="m-label">文字の大きさ</div>
      <div class="seg">
        <button class="seg-btn ${prefs.fs==="m"?"on":""}" data-act="set-fs" data-v="m">標準</button>
        <button class="seg-btn ${prefs.fs==="l"?"on":""}" data-act="set-fs" data-v="l">大きめ</button>
        <button class="seg-btn ${prefs.fs==="xl"?"on":""}" data-act="set-fs" data-v="xl">特大</button>
      </div>
      <div class="m-label">テーマカラー</div>
      <div class="pick-row" style="justify-content:space-around">
        ${THEMES.map(th=>`<button class="theme-btn ${prefs.theme===th.id?"on":""}" data-act="set-theme" data-v="${th.id}"><span class="theme-dot" style="background:${th.color}"></span>${th.label}</button>`).join("")}
      </div>
      <div class="m-label">セキュリティ</div>
      <button class="big-btn" style="width:100%;background:var(--card);color:var(--sub);border:2px solid var(--line);margin-bottom:8px" data-act="open-passchange">🔑 パスコードを変更</button>
      <button class="big-btn" style="width:100%;background:var(--card);color:var(--teal);border:2px solid var(--teal)" data-act="lock-manual">🔒 今すぐロックする</button>
      <p style="font-size:12px;color:var(--faint);line-height:1.7;margin-top:12px">🔊 読み上げは各トピックの画面から。${AUTO_LOCK_MIN}分操作がないと自動ロックします。</p>
      <div class="btn-row"><button class="big-btn" style="flex:1;background:var(--teal);color:#fff" data-act="close-modal">とじる</button></div>
      <button class="text-link" data-act="open-about" style="width:100%">利用上の注意・プライバシー</button>
    </div></div>`;
  }
  if(modal==="passchange"){
    return `
    <div class="overlay" data-act="close-modal"><div class="modal" data-stop>
      <h2>🔑 パスコードの変更</h2>
      <p style="font-size:12.5px;color:var(--sub);line-height:1.7;margin-bottom:8px"><b style="color:var(--danger)">忘れるとデータを復元できません。</b></p>
      <div class="m-label">新しいパスコード(4文字以上)</div>
      <input class="input" id="m-pass1" type="password" autocomplete="new-password">
      <div class="m-label">もう一度入力</div>
      <input class="input" id="m-pass2" type="password" autocomplete="new-password">
      <div class="lock-error" id="m-pass-err"></div>
      <div class="btn-row">
        <button class="big-btn" style="flex:1;background:var(--line);color:var(--sub)" data-act="close-modal">やめる</button>
        <button class="big-btn" style="flex:2;background:var(--teal);color:#fff" data-act="passchange-save">変更する</button>
      </div>
    </div></div>`;
  }
  if(modal==="about"){
    return `
    <div class="overlay" data-act="close-modal"><div class="modal" data-stop>
      <h2>ℹ️ このアプリについて</h2>
      <div style="font-size:13px;line-height:1.9;color:var(--ink)">
        <p style="margin-bottom:10px"><b>サポートカード</b> v${APP_VERSION}<br>お子さんの特徴を、必要な情報だけサッと伝えるアプリです。</p>
        <p style="font-weight:900;margin-bottom:4px">🔐 プライバシー</p>
        <p style="margin-bottom:10px;color:var(--sub)">すべてのデータは、お使いの端末のブラウザ内だけに、暗号化して保存されます。インターネットには一切送信されません。広告・解析もありません。</p>
        <p style="font-weight:900;margin-bottom:4px">⚠️ 大切な注意</p>
        <p style="margin-bottom:10px;color:var(--sub)">パスコードを忘れるとデータは復元できません。また、データは端末ごとに保存されるため、機種変更やブラウザのデータ消去で失われます。「このチームを共有」での定期バックアップを強くおすすめします。本アプリは医療判断の代わりにはなりません。緊急時は119へ。</p>
        <p style="font-weight:900;margin-bottom:4px">📄 ライセンス</p>
        <p style="color:var(--sub)">MIT License。詳細はPRIVACY.mdをご覧ください。</p>
      </div>
      <div class="btn-row"><button class="big-btn" style="flex:1;background:var(--teal);color:#fff" data-act="close-modal">とじる</button></div>
    </div></div>`;
  }
  return "";
}

// ================= 入力保持 =================
function keepModalInputs(){
  if(modal==="person" && modalDraft){
    const n=document.getElementById("m-name"), o=document.getElementById("m-note");
    if(n) modalDraft.name=n.value; if(o) modalDraft.note=o.value;
  }
  if(modal==="topic" && modalDraft){ const t=document.getElementById("m-topic-title"); if(t) modalDraft.title=t.value; }
  if(modal==="team" && modalDraft){ const t=document.getElementById("t-name"); if(t) modalDraft.name=t.value; }
}
function keepDraftInputs(){
  document.querySelectorAll("[data-draft-label]").forEach(el=>{ draft[+el.dataset.draftLabel].label = el.value; });
  document.querySelectorAll("[data-draft-value]").forEach(el=>{ draft[+el.dataset.draftValue].value = el.value; });
}

// ================= イベント =================
function bindEvents(){
  app.querySelectorAll("[data-stop]").forEach(el=>el.addEventListener("click",e=>e.stopPropagation()));
  app.querySelectorAll("[data-act]").forEach(el=>{
    el.addEventListener("click",(e)=>{ e.stopPropagation(); handle(el.dataset.act, el.dataset); });
    if(el.getAttribute("role")==="button"){
      el.addEventListener("keydown",(e)=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); e.stopPropagation(); handle(el.dataset.act, el.dataset); } });
    }
  });
  const lk=document.getElementById("lk-pass"); if(lk) lk.addEventListener("keydown",e=>{ if(e.key==="Enter") handle("unlock",{}); });
  const su=document.getElementById("su-pass2"); if(su) su.addEventListener("keydown",e=>{ if(e.key==="Enter") handle("setup-go",{}); });
}
document.addEventListener("keydown",(e)=>{ if(e.key==="Escape" && modal){ modal=null; modalDraft=null; render(); } });

async function handle(act, ds){
  const tm = getTeam(), p = getPerson();
  switch(act){
    // ---- 認証 ----
    case "setup-go":{
      const v1=document.getElementById("su-pass1").value, v2=document.getElementById("su-pass2").value;
      if(v1.length<4){ screenError="パスコードは4文字以上にしてください"; render(); return; }
      if(v1!==v2){ screenError="2回の入力が一致しません"; render(); return; }
      screenError=""; await setupNew(v1); break;
    }
    case "unlock":{
      const v=document.getElementById("lk-pass")?.value||""; if(!v) return;
      await unlock(v); break;
    }
    case "lock-manual": case "lock-now": modal=null; lockNow(); break;

    // ---- チーム ----
    case "enter-team": view={teamId:ds.id, screen:"list", personId:null, topicId:null, editing:false, organize:false}; stage="ready"; render(); break;
    case "back-home": stopSpeak(); view.teamId=null; stage="home"; render(); break;
    case "open-team-create": modal="team"; modalDraft={isNew:true,name:"",emoji:"🏠",color:"#2F8F83"}; render(); break;
    case "edit-team": modal="team"; modalDraft={isNew:false,id:tm.id,name:tm.name,emoji:tm.emoji,color:tm.color}; render(); break;
    case "pick-team-emoji": keepModalInputs(); modalDraft.emoji=ds.v; render(); break;
    case "pick-team-color": keepModalInputs(); modalDraft.color=ds.v; render(); break;
    case "create-team":{
      keepModalInputs();
      if(!modalDraft.name.trim()){ document.getElementById("t-err").textContent="チーム名を入力してください"; return; }
      const nt=normalizeTeam({id:uid(),name:modalDraft.name.trim(),emoji:modalDraft.emoji,color:modalDraft.color,people:[]});
      teams.push(nt); modal=null; await save();
      view={teamId:nt.id,screen:"list",personId:null,topicId:null,editing:false,organize:false}; stage="ready"; render(); break;
    }
    case "save-team-edit":{
      keepModalInputs();
      if(!modalDraft.name.trim()){ document.getElementById("t-err").textContent="チーム名を入力してください"; return; }
      Object.assign(tm,{name:modalDraft.name.trim(),emoji:modalDraft.emoji,color:modalDraft.color});
      modal=null; await save(); render(); break;
    }
    case "del-team":{
      if(!confirm(`「${tm.name}」を削除しますか?\nこのチームのカードもすべて消えます。`)) return;
      teams=teams.filter(t=>t.id!==tm.id); modal=null; view.teamId=null; stage="home"; await save(); render(); break;
    }

    // ---- カードのコピー ----
    case "open-copyto": modal="copyto"; render(); break;
    case "copy-card":{
      const target=teams.find(t=>t.id===ds.id); const copy=structuredClone(p); copy.id=uid();
      target.people.push(copy); modal=null; await save();
      alert(`「${target.name}」に ${p.name} のカードをコピーしました。\n※コピー後は独立したカードです。`); break;
    }

    // ---- 設定・読み上げ ----
    case "settings": modal="settings"; render(); break;
    case "open-about": modal="about"; render(); break;
    case "set-fs": prefs.fs=ds.v; applyPrefs(); render(); break;
    case "set-theme": prefs.theme=ds.v; applyPrefs(); render(); break;
    case "open-passchange": modal="passchange"; render(); break;
    case "passchange-save":{
      const v1=document.getElementById("m-pass1").value, v2=document.getElementById("m-pass2").value;
      const err=document.getElementById("m-pass-err");
      if(v1.length<4){ err.textContent="4文字以上にしてください"; return; }
      if(v1!==v2){ err.textContent="2回の入力が一致しません"; return; }
      salt = crypto.getRandomValues(new Uint8Array(16));
      cryptoKey = await deriveKey(v1, salt);
      await save(); modal=null; alert("パスコードを変更しました。"); render(); break;
    }
    case "speak":{ if(speaking){ stopSpeak(); render(); break; } speakTopic(p, getTopic(p)); render(); break; }

    // ---- 画面移動 ----
    case "open-person": stopSpeak(); view={...view, screen:"person", personId:ds.id, organize:false}; render(); break;
    case "back-list": stopSpeak(); view={...view, screen:"list", personId:null}; render(); break;
    case "open-topic": if(view.organize) return; stopSpeak(); view={...view, screen:"detail", topicId:ds.id, editing:false}; render(); break;
    case "back-person": stopSpeak(); view={...view, screen:"person", topicId:null, editing:false}; render(); break;

    // ---- 内容編集 ----
    case "start-edit":{ const e=p.topics[view.topicId]||[]; draft=e.length?e.map(x=>({...x})):[{label:"",value:""}]; view.editing=true; render(); break; }
    case "cancel-edit": view.editing=false; render(); break;
    case "draft-add": keepDraftInputs(); draft.push({label:"",value:""}); render(); break;
    case "draft-remove": keepDraftInputs(); draft.splice(+ds.i,1); if(!draft.length)draft=[{label:"",value:""}]; render(); break;
    case "save-edit": keepDraftInputs(); p.topics[view.topicId]=draft.filter(d=>d.label.trim()||d.value.trim()); view.editing=false; await save(); render(); break;

    // ---- 人物 ----
    case "add-person": modal="person"; modalDraft={isNew:true,name:"",emoji:"🌸",note:"",photo:null}; render(); break;
    case "edit-person": modal="person"; modalDraft={id:p.id,name:p.name,emoji:p.emoji,note:p.note||"",photo:p.photo||null}; render(); break;
    case "pick-emoji": keepModalInputs(); modalDraft.emoji=ds.v; render(); break;
    case "pick-photo": keepModalInputs(); document.getElementById("photoInput").click(); break;
    case "clear-photo": keepModalInputs(); modalDraft.photo=null; render(); break;
    case "save-person":{
      keepModalInputs(); if(!modalDraft.name.trim()) return;
      if(modalDraft.isNew) tm.people.push({id:uid(),name:modalDraft.name.trim(),emoji:modalDraft.emoji,note:modalDraft.note.trim(),photo:modalDraft.photo,topicDefs:structuredClone(DEFAULT_TOPICS),topics:{}});
      else Object.assign(tm.people.find(x=>x.id===modalDraft.id),{name:modalDraft.name.trim(),emoji:modalDraft.emoji,note:modalDraft.note.trim(),photo:modalDraft.photo});
      modal=null; await save(); render(); break;
    }
    case "del-person":{
      keepModalInputs(); if(!confirm(`${modalDraft.name} のカードを削除しますか?`)) return;
      tm.people=tm.people.filter(x=>x.id!==modalDraft.id); modal=null; view={...view,screen:"list",personId:null}; await save(); render(); break;
    }
    case "close-modal": modal=null; modalDraft=null; render(); break;

    // ---- トピック ----
    case "toggle-organize": view.organize=!view.organize; render(); break;
    case "add-topic": modal="topic"; modalDraft={title:"",icon:"📌",color:"#5B8DB8"}; render(); break;
    case "pick-icon": keepModalInputs(); modalDraft.icon=ds.v; render(); break;
    case "pick-color": keepModalInputs(); modalDraft.color=ds.v; render(); break;
    case "save-topic":{
      keepModalInputs(); if(!modalDraft.title.trim()) return;
      p.topicDefs.push({id:uid(),icon:modalDraft.icon,title:modalDraft.title.trim(),color:modalDraft.color,desc:""}); modal=null; await save(); render(); break;
    }
    case "del-topic":{
      const t=p.topicDefs.find(x=>x.id===ds.id);
      if(!confirm(`「${t.title}」を削除しますか?\n書かれている内容も消えます。`)) return;
      p.topicDefs=p.topicDefs.filter(x=>x.id!==ds.id); delete p.topics[ds.id]; await save(); render(); break;
    }
    case "move-up": case "move-down":{
      const i=p.topicDefs.findIndex(x=>x.id===ds.id), j=act==="move-up"?i-1:i+1;
      if(j<0||j>=p.topicDefs.length) return;
      [p.topicDefs[i],p.topicDefs[j]]=[p.topicDefs[j],p.topicDefs[i]]; await save(); render(); break;
    }

    // ---- 共有(暗号化ファイルの書き出し/読み込み) ----
    case "share-team":{
      const pass = prompt("共有用のパスコードを決めてください(相手に別途伝えます)");
      if(!pass) return;
      if(pass.length<4){ alert("4文字以上にしてください"); return; }
      const s = crypto.getRandomValues(new Uint8Array(16));
      const k = await deriveKey(pass, s);
      const enc = await encryptJson({team:tm}, k);
      const out = { app:"support-card", type:"team-share", v:1, salt:b64(s), iv:enc.iv, data:enc.data };
      const blob = new Blob([JSON.stringify(out)],{type:"application/json"});
      const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
      a.download=`${tm.name}.scard`; a.click(); URL.revokeObjectURL(a.href);
      alert("共有ファイル(.scard)を書き出しました。\nこのファイルと、決めたパスコードを相手に渡してください。\n相手は「読み込み」から取り込めます。"); break;
    }
    case "import": document.getElementById("importInput").click(); break;

    case "print": buildPrint(p); window.print(); break;
  }
}

// ---- 写真選択 ----
document.getElementById("photoInput").addEventListener("change", async (e)=>{
  const f=e.target.files?.[0]; e.target.value=""; if(!f||!modalDraft) return;
  try{ modalDraft.photo=await readPhoto(f); render(); }catch(err){ alert("写真の読み込みに失敗しました"); }
});

// ---- 読み込み(.scard / バックアップ) ----
document.getElementById("importInput").addEventListener("change",(e)=>{
  const f=e.target.files?.[0]; e.target.value=""; if(!f) return;
  const r=new FileReader();
  r.onload=async ()=>{
    try{
      const data=JSON.parse(r.result);
      if(data.type==="team-share" && data.salt){
        const pass=prompt("共有ファイルのパスコードを入力してください");
        if(!pass) return;
        try{
          const k=await deriveKey(pass, unb64(data.salt));
          const obj=await decryptJson(data, k);
          const nt=normalizeTeam(obj.team); nt.id=uid();
          if(!confirm(`「${nt.name}」を新しいチームとして追加します。よろしいですか?`)) return;
          teams.push(nt); await save();
          view={teamId:nt.id,screen:"list",personId:null,topicId:null,editing:false,organize:false}; stage="ready"; render();
        }catch(err){ alert("パスコードがちがうか、ファイルが壊れています。"); }
        return;
      }
      alert("このファイルは読み込めません。サポートカードの共有ファイル(.scard)を選んでください。");
    }catch(err){ alert("読み込めませんでした。"); }
  };
  r.readAsText(f);
});

function buildPrint(p){
  const el=document.getElementById("print");
  el.innerHTML=`
    <h1>${esc(p.emoji||"")} ${esc(p.name)} のサポートカード</h1>
    <div class="pr-note">${esc(p.note||"")}(印刷日:${new Date().toLocaleDateString("ja-JP")})</div>
    ${p.topicDefs.map(t=>{ const es=p.topics[t.id]||[]; if(!es.length) return "";
      return `<div class="pr-topic"><h2 style="background:${t.color}">${esc(t.icon)} ${esc(t.title)}</h2>
        ${es.map(e=>`<div class="pr-entry">${e.label?`<b>${esc(e.label)}</b>`:""}<div>${esc(e.value)}</div></div>`).join("")}</div>`;}).join("")}`;
}

// ================= 起動 =================
loadPrefs(); applyPrefs();
(function boot(){
  const has = localStorage.getItem(STORE_KEY);
  stage = has ? "locked" : "setup-pass";
  render();
})();
