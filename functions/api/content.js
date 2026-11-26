const headers={'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers});
const enc=new TextEncoder();
async function equal(a,b){const x=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(a))),y=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(b)));let d=0;for(let i=0;i<x.length;i++)d|=x[i]^y[i];return d===0}
export async function onRequest({request,env}){
try{
const u=new URL(request.url);
if(!env.DB)return reply({error:'DB binding missing'},503);
if(request.method==='GET'){const row=await env.DB.prepare("SELECT payload FROM portfolio_content WHERE id=1").first().catch(()=>null);return reply(row?JSON.parse(row.payload):{});}
if(request.method!=='PUT')return reply({error:'Method not allowed'},405);
if(request.headers.get('Origin')!==u.origin)return reply({error:'Invalid origin'},403);
if(!env.ADMIN_PASSWORD||env.ADMIN_PASSWORD.length<16)return reply({error:'Configure ADMIN_PASSWORD secret (16+ characters)'},503);
const auth=request.headers.get('Authorization')||'';
if(!auth.startsWith('Basic '))return reply({error:'Unauthorized'},401);
let credential;try{credential=new TextDecoder().decode(Uint8Array.from(atob(auth.slice(6)),c=>c.charCodeAt(0)))}catch{return reply({error:'Unauthorized'},401)}
if(!await equal(credential,'admin:'+env.ADMIN_PASSWORD))return reply({error:'Unauthorized'},401);
const body=await request.text();if(body.length>1500000)return reply({error:'Too large'},413);
const data=JSON.parse(body);
if(!data||typeof data!=='object'||Array.isArray(data))return reply({error:'Invalid content'},400);
const allowed=['texts','projects','theme','seo'];
if(Object.keys(data).some(k=>!allowed.includes(k)))return reply({error:'Invalid field'},400);
await env.DB.prepare('CREATE TABLE IF NOT EXISTS portfolio_content (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)').run();
await env.DB.prepare('INSERT INTO portfolio_content(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload').bind(JSON.stringify(data)).run();
return reply({ok:true});
}catch(e){return reply({error:'Request failed'},500)}
}