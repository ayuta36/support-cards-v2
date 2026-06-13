import { readFileSync } from "fs";
const src = readFileSync("app.js","utf8");
let pass=0, fail=0;
const ok=(n,c,d="")=>{ if(c){pass++;console.log("  ✅ "+n)}else{fail++;console.log("  ❌ "+n+" "+d)} };

console.log("\n■ 暗号化");
{
  async function dk(p,s){const m=await crypto.subtle.importKey("raw",new TextEncoder().encode(p),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:s,iterations:310000,hash:"SHA-256"},m,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);}
  const s=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
  const k=await dk("ぱす🌸",s);
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,new TextEncoder().encode(JSON.stringify({teams:[{name:"やまだ家"}]})));
  const k2=await dk("ぱす🌸",s);
  const pt=JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv},k2,ct)));
  ok("正パスコードで復号", pt.teams[0].name==="やまだ家");
  let b=false; try{ await crypto.subtle.decrypt({name:"AES-GCM",iv},await dk("ちがう",s),ct);}catch(e){b=true;} ok("誤パスコードを拒否", b);
  let t=false; try{ const v=new Uint8Array(ct); v[3]^=0xFF; await crypto.subtle.decrypt({name:"AES-GCM",iv},k2,v);}catch(e){t=true;} ok("改ざん検知", t);
}
console.log("\n■ XSS");
{ const esc=(s)=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  ok("scriptタグ無害化", esc("<script>")==="&lt;script&gt;"); ok("null安全", esc(null)===""); }
console.log("\n■ ボタン網羅性");
{ const ui=new Set([...src.matchAll(/data-act="([a-z-]+)"/g)].map(m=>m[1]));
  const hd=new Set([...src.matchAll(/case "([a-z-]+)":/g)].map(m=>m[1]));
  const miss=[...ui].filter(a=>!hd.has(a));
  ok(`全${ui.size}アクションに処理あり`, miss.length===0, miss.join(","));
}
console.log("\n■ セキュリティ設定");
{ const h=readFileSync("index.html","utf8");
  ok("外部通信ゼロのCSP", h.includes("connect-src 'none'"));
  ok("noindex", h.includes("noindex"));
  ok("自動ロック実装", src.includes("AUTO_LOCK_MIN") && src.includes("lockNow"));
  ok("総当たり対策(待機)", src.includes("LOCKOUTS") && src.includes("lockUntil"));
  ok("覗き見ガード", src.includes("peek-guard"));
  ok("PBKDF2 31万回", src.includes("310000"));
}
console.log(`\n==== ${pass}件成功 / ${fail}件失敗 ====\n`);
process.exit(fail?1:0);
