'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib');
const {DatabaseSync}=require('node:sqlite');
const PROD=process.env.NODE_ENV==='production',MAX=5*1024*1024;
const DATA=process.env.DATA_DIR||path.join(__dirname,'data'),CERTS=path.join(DATA,'certs'),PUB=path.join(__dirname,'public');
fs.mkdirSync(CERTS,{recursive:true,mode:0o700});
const db=new DatabaseSync(path.join(DATA,'cadetinfo.db'));
db.exec(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));
const q=(s,...p)=>db.prepare(s).all(...p),q1=(s,...p)=>db.prepare(s).get(...p),run=(s,...p)=>db.prepare(s).run(...p);
const META={CAMP_TYPES:['CATC','RDC','TSC','NIC','EBSB','ALC','AAC','YEP','ATC','Other'],STATUSES:['Completed','Ongoing','Upcoming'],WINGS:['Army','Navy','Air Wing'],GENDERS:['Male','Female','Other'],
 RANKS:['Cadet','Lance Corporal','Corporal','Sergeant','Company Quarter Master Sergeant','Company Sergeant Major','Under Officer','Senior Under Officer'],
 CERT_TYPES:['Camp Certificate','A Certificate','B Certificate','C Certificate','Achievement','Other'],NCC_YEARS:['1st Year','2nd Year','3rd Year']};
class HttpError extends Error{constructor(s,m){super(m);this.status=s}}
const bad=(m,s=400)=>new HttpError(s,m),S=(v,n=200)=>String(v??'').trim().slice(0,n),int=v=>/^\d{1,12}$/.test(String(v))?+v:-1;
const okDate=s=>/^\d{4}-\d{2}-\d{2}$/.test(s)&&!isNaN(Date.parse(s));
// ---------- crypto / sessions ----------
const hashPw=p=>{const s=crypto.randomBytes(16);return s.toString('hex')+':'+crypto.scryptSync(p,s,64).toString('hex')};
const checkPw=(p,st)=>{const [s,h]=st.split(':');return crypto.timingSafeEqual(crypto.scryptSync(p,Buffer.from(s,'hex'),64),Buffer.from(h,'hex'))};
const DUMMY=hashPw('dummy-password'),sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const cookies=req=>Object.fromEntries((req.headers.cookie||'').split(';').map(c=>c.trim().split(/=(.*)/s).slice(0,2)).filter(a=>a[0]&&a[1]));
const getUser=req=>{const t=cookies(req).sid;if(!t)return null;const u=q1('SELECT u.*,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?',sha(t));return u&&u.expires_at>Date.now()&&u.active?u:null};
const tries=new Map(),limited=k=>{const t=Date.now(),a=(tries.get(k)||[]).filter(x=>t-x<6e5);tries.set(k,a);return a.length>=8};
const ip=req=>process.env.TRUST_PROXY?String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress:req.socket.remoteAddress;
const audit=(u,action,target='',detail='')=>run('INSERT INTO audit_log(actor_id,actor_label,action,target,detail) VALUES(?,?,?,?,?)',u?u.id:null,u?(u.role==='CADET'?u.cadet_id:u.ano_id||u.email):'anonymous',action,S(target,100),S(detail,300));
// ---------- users ----------
function addUser({name,email,password,role,cadet_id=null,ano_id=null,unit_id=null}){
  db.exec('BEGIN');try{
    const r=run('INSERT INTO users(name,email,password_hash,role,cadet_id,ano_id,unit_id) VALUES(?,?,?,?,?,?,?)',name,email,hashPw(password),role,cadet_id,ano_id,unit_id),id=Number(r.lastInsertRowid);
    if(role==='CADET'){const un=q1('SELECT * FROM units WHERE id=?',unit_id),ano=q1("SELECT name FROM users WHERE role='ANO' AND unit_id=? LIMIT 1",unit_id);
      run('INSERT INTO cadet_profiles(user_id,cadet_id,full_name,email,college,ncc_unit,battalion,ano_name) VALUES(?,?,?,?,?,?,?,?)',id,cadet_id,name,email,un.institution,un.unit_name,un.battalion,ano?ano.name:'')}
    db.exec('COMMIT');return id}catch(e){db.exec('ROLLBACK');throw e}}
const pub=u=>({id:u.id,name:u.name,email:u.email,role:u.role,cadet_id:u.cadet_id,ano_id:u.ano_id,unit:u.unit_id?q1('SELECT id,unit_name,battalion,institution FROM units WHERE id=?',u.unit_id):null});
// ---------- profile completion ----------
const PERS=['full_name','student_id','dob','gender','college','department','year','phone','email','address'],NCC=['wing','enrollment_number','enrollment_date','ncc_rank','current_ncc_year','ano_name'];
function completion(uid){const p=q1('SELECT * FROM cadet_profiles WHERE user_id=?',uid)||{},camps=q('SELECT experience FROM camps WHERE user_id=?',uid),nc=q1('SELECT COUNT(*) n FROM certificates WHERE user_id=?',uid).n;
  const f=a=>a.filter(k=>String(p[k]??'').trim()).length/a.length,max=[25,25,20,15,15],got=[25*f(PERS),25*f(NCC),camps.length?20:0,camps.some(c=>c.experience)?15:0,nc?15:0],lab=['personal information','NCC information','a camp','a camp experience','a certificate'];
  return {pct:Math.round(got.reduce((a,b)=>a+b,0)),missing:lab.filter((_,i)=>got[i]<max[i])}}
// ---------- authorization (the single source of truth) ----------
const authorizedCadet=(u,id)=>{const c=q1("SELECT * FROM users WHERE id=? AND role='CADET'",int(id));
  if(!c||!(u.role==='SUPER_ADMIN'||(u.role==='ANO'&&u.unit_id!=null&&u.unit_id===c.unit_id)))throw bad('Not found',404);return c};
const scoped=u=>u.role==='SUPER_ADMIN'?q("SELECT * FROM users WHERE role='CADET'"):q("SELECT * FROM users WHERE role='CADET' AND unit_id=?",u.unit_id);
function summary(c){const p=q1('SELECT * FROM cadet_profiles WHERE user_id=?',c.id),camps=q('SELECT camp_name,camp_type FROM camps WHERE user_id=?',c.id);
  const {user_id,...rest}=p;return {...rest,id:c.id,active:c.active,camps:camps.length,camp_names:camps.map(x=>x.camp_name),camp_types:camps.map(x=>x.camp_type),
  certificates:q1('SELECT COUNT(*) n FROM certificates WHERE user_id=?',c.id).n,completion:completion(c.id).pct}}
// ---------- file helpers ----------
const sniff=b=>b.subarray(0,4).toString('latin1')==='%PDF'?{ext:'pdf',mime:'application/pdf'}:(b[0]===0xFF&&b[1]===0xD8&&b[2]===0xFF)?{ext:'jpg',mime:'image/jpeg'}:b.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]))?{ext:'png',mime:'image/png'}:null;
function readBody(req,max,msg='Request too large'){return new Promise((ok,no)=>{const ch=[];let n=0,over=false;req.on('data',c=>{n+=c.length;if(n>max){over=true;ch.length=0}else if(!over)ch.push(c)});req.on('end',()=>over?no(new HttpError(413,msg)):ok(Buffer.concat(ch)));req.on('error',no)})}
const jsonBody=async req=>{const b=await readBody(req,1e6);try{return JSON.parse(b.toString()||'{}')||{}}catch{throw bad('Invalid JSON')}};
function multipart(buf,ct){const m=/boundary=(?:"([^"]+)"|([^;]+))/i.exec(ct||'');if(!m)throw bad('Invalid upload');const b=Buffer.from('--'+(m[1]||m[2])),out={fields:{},file:null};let pos=buf.indexOf(b);
  while(pos>=0){const st=pos+b.length;if(buf.subarray(st,st+2).toString()==='--')break;const he=buf.indexOf('\r\n\r\n',st);if(he<0)break;const head=buf.subarray(st+2,he).toString('utf8'),next=buf.indexOf(b,he+4);if(next<0)break;const body=buf.subarray(he+4,next-2);
    const name=/name="([^"]*)"/.exec(head),fn=/filename="([^"]*)"/.exec(head);
    if(fn)out.file={name:fn[1].split(/[\\/]/).pop().replace(/[\x00-\x1f]/g,'').slice(0,120)||'certificate',data:body};else if(name)out.fields[name[1]]=body.toString('utf8');pos=next}
  return out}
// ---------- Excel (.xlsx) writer, no dependencies ----------
function zip(files){const parts=[],cd=[];let off=0;for(const [name,content] of files){const n=Buffer.from(name),d=Buffer.from(content),crc=zlib.crc32(d),h=Buffer.alloc(30);
  h.writeUInt32LE(0x04034b50,0);h.writeUInt16LE(20,4);h.writeUInt16LE(0x0800,6);h.writeUInt16LE(33,12);h.writeUInt32LE(crc,14);h.writeUInt32LE(d.length,18);h.writeUInt32LE(d.length,22);h.writeUInt16LE(n.length,26);parts.push(h,n,d);
  const c=Buffer.alloc(46);c.writeUInt32LE(0x02014b50,0);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(0x0800,8);c.writeUInt16LE(33,14);c.writeUInt32LE(crc,16);c.writeUInt32LE(d.length,20);c.writeUInt32LE(d.length,24);c.writeUInt16LE(n.length,28);c.writeUInt32LE(off,42);cd.push(c,n);off+=30+n.length+d.length}
  const cdb=Buffer.concat(cd),e=Buffer.alloc(22);e.writeUInt32LE(0x06054b50,0);e.writeUInt16LE(files.length,8);e.writeUInt16LE(files.length,10);e.writeUInt32LE(cdb.length,12);e.writeUInt32LE(off,16);return Buffer.concat([...parts,cdb,e])}
const xe=s=>String(s).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g,'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const safe=v=>typeof v==='number'?v:/^[=+\-@\t\r]/.test(String(v??''))?"'"+v:String(v??'');
function xlsx(rows){const X='<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',col=i=>String.fromCharCode(65+i);
  const sheet=X+'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'+rows.map((r,i)=>`<row r="${i+1}">`+r.map((v,c)=>typeof v==='number'?`<c r="${col(c)}${i+1}"><v>${v}</v></c>`:`<c r="${col(c)}${i+1}" t="inlineStr"><is><t>${xe(v)}</t></is></c>`).join('')+'</row>').join('')+'</sheetData></worksheet>',R='http://schemas.openxmlformats.org/officeDocument/2006/relationships';
  return zip([['[Content_Types].xml',X+'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'],
  ['_rels/.rels',X+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${R}/officeDocument" Target="xl/workbook.xml"/></Relationships>`],
  ['xl/workbook.xml',X+`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="${R}"><sheets><sheet name="Cadets" sheetId="1" r:id="rId1"/></sheets></workbook>`],
  ['xl/_rels/workbook.xml.rels',X+`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${R}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`],['xl/worksheets/sheet1.xml',sheet]])}
const csv=rows=>rows.map(r=>r.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(',')).join('\r\n');
// ---------- tiny router ----------
const routes=[],R=(m,p,roles,fn)=>routes.push({m,re:new RegExp('^'+p.replace(/:(\w+)/g,'(?<$1>[^/]+)')+'$'),roles,fn});
const send=(res,s,o)=>{res.writeHead(s,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(o))};
const ANO=['ANO','SUPER_ADMIN'];
// ----- public / auth -----
R('GET','/api/meta',null,()=>({...META,units:q('SELECT id,unit_name,battalion,institution FROM units ORDER BY unit_name'),needCode:!!process.env.REGISTRATION_CODE}));
R('GET','/api/auth/me',null,({user})=>({user:user?pub(user):null}));
R('POST','/api/auth/register',null,async({req})=>{const b=await jsonBody(req);
  if(process.env.REGISTRATION_CODE&&S(b.code)!==process.env.REGISTRATION_CODE)throw bad('Invalid registration code',403);
  const name=S(b.name,120),cid=S(b.cadet_id,30),email=S(b.email,120).toLowerCase(),pw=String(b.password||''),unit=q1('SELECT id FROM units WHERE id=?',int(b.unit_id));
  if(!name)throw bad('Full name is required');if(!/^[A-Za-z0-9._-]{3,30}$/.test(cid))throw bad('Cadet ID must be 3-30 letters, numbers, . _ -');
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email))throw bad('Valid email is required');if(pw.length<8||pw.length>128)throw bad('Password must be 8-128 characters');if(!unit)throw bad('Please choose your NCC unit');
  try{const id=addUser({name,email,password:pw,role:'CADET',cadet_id:cid,unit_id:unit.id});audit({id,role:'CADET',cadet_id:cid},'registered',cid)}catch(e){if(/UNIQUE/.test(e.message))throw bad('Cadet ID or email is already registered',409);throw e}
  return {ok:true}});
R('POST','/api/auth/login',null,async({req,res})=>{const b=await jsonBody(req),id=S(b.identifier,120),portal=b.portal==='ano'?'ano':'cadet',key=ip(req)+'|'+id.toLowerCase();
  if(limited(key))throw bad('Too many attempts. Please try again in 10 minutes.',429);
  const roles=portal==='ano'?ANO:['CADET'],u=q('SELECT * FROM users WHERE email=? OR cadet_id=? OR ano_id=?',id,id,id).find(x=>roles.includes(x.role)),ok=checkPw(String(b.password||'').slice(0,200),u?u.password_hash:DUMMY);
  if(!u||!ok||!u.active){tries.get(key).push(Date.now());audit(null,'login_failed',id);throw bad('Invalid ID or password',401)}
  run('DELETE FROM sessions WHERE expires_at<?',Date.now());const t=crypto.randomBytes(32).toString('base64url');run('INSERT INTO sessions(id,user_id,expires_at) VALUES(?,?,?)',sha(t),u.id,Date.now()+8*36e5);
  run("UPDATE users SET prev_login=last_login,last_login=datetime('now') WHERE id=?",u.id);audit(u,'login');
  res.setHeader('Set-Cookie',`sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${PROD?'; Secure':''}`);return {user:pub(u)}});
R('POST','/api/auth/logout',[],({req,res})=>{const t=cookies(req).sid;if(t)run('DELETE FROM sessions WHERE id=?',sha(t));res.setHeader('Set-Cookie','sid=; HttpOnly; Path=/; Max-Age=0');return {ok:true}});
// ----- cadet: only ever operates on session user (no cadet id is accepted from the client) -----
const PF={student_id:60,full_name:120,dob:10,gender:20,college:150,department:100,year:2,phone:20,email:120,address:300,wing:20,enrollment_number:60,enrollment_date:10,ncc_rank:60,current_ncc_year:20,ano_name:100};
R('GET','/api/me',['CADET'],({user})=>{const camps=q('SELECT number_of_days d FROM camps WHERE user_id=?',user.id);
  return {user:pub(user),profile:q1('SELECT * FROM cadet_profiles WHERE user_id=?',user.id),completion:completion(user.id),camps:camps.length,days:camps.reduce((a,c)=>a+c.d,0),certificates:q1('SELECT COUNT(*) n FROM certificates WHERE user_id=?',user.id).n}});
R('PUT','/api/me/profile',['CADET'],async({req,user})=>{const b=await jsonBody(req),d={};for(const k in PF)if(k in b)d[k]=S(b[k],PF[k]);
  const inL=(v,l)=>!v||l.includes(v);
  if('full_name'in d&&!d.full_name)throw bad('Full name is required');
  for(const k of['dob','enrollment_date'])if(d[k]&&!okDate(d[k]))throw bad('Invalid date');if(d.dob&&Date.parse(d.dob)>=Date.now())throw bad('Date of birth must be in the past');
  if(d.phone&&!/^\+?[\d\s-]{8,15}$/.test(d.phone))throw bad('Invalid phone number');if(d.email&&!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(d.email))throw bad('Invalid email');
  if(!inL(d.gender,META.GENDERS)||!inL(d.wing,META.WINGS)||!inL(d.ncc_rank,META.RANKS)||!inL(d.current_ncc_year,META.NCC_YEARS)||(d.year&&!/^[1-6]$/.test(d.year)))throw bad('Invalid selection');
  const ks=Object.keys(d);if(ks.length){run(`UPDATE cadet_profiles SET ${ks.map(k=>k+'=?').join(',')},updated_at=datetime('now') WHERE user_id=?`,...ks.map(k=>d[k]),user.id);if(d.full_name)run('UPDATE users SET name=? WHERE id=?',d.full_name,user.id)}
  audit(user,'profile_updated',user.cadet_id);return {ok:true}});
function campData(b){const d={camp_name:S(b.camp_name,120),camp_type:S(b.camp_type),location:S(b.location,120),from_date:S(b.from_date,10),to_date:S(b.to_date,10),organizing_unit:S(b.organizing_unit,120),certificate_number:S(b.certificate_number,60),status:S(b.status),experience:S(b.experience,1000)};
  if(!d.camp_name||!d.location)throw bad('Camp name and location are required');if(!META.CAMP_TYPES.includes(d.camp_type))throw bad('Invalid camp type');if(!META.STATUSES.includes(d.status))throw bad('Invalid camp status');
  if(!okDate(d.from_date)||!okDate(d.to_date))throw bad('Valid From and To dates are required');d.number_of_days=Math.round((Date.parse(d.to_date)-Date.parse(d.from_date))/864e5);if(d.number_of_days<0)throw bad('To date must not be before From date');return d}
const CK=['camp_name','camp_type','location','from_date','to_date','number_of_days','organizing_unit','certificate_number','status','experience'];
R('GET','/api/me/camps',['CADET'],({user})=>q('SELECT * FROM camps WHERE user_id=? ORDER BY from_date DESC',user.id));
R('POST','/api/me/camps',['CADET'],async({req,res,user})=>{const d=campData(await jsonBody(req));if(q1('SELECT COUNT(*) n FROM camps WHERE user_id=?',user.id).n>=100)throw bad('Camp limit reached');
  const r=run(`INSERT INTO camps(user_id,${CK}) VALUES(?,${CK.map(()=>'?')})`,user.id,...CK.map(k=>d[k]));audit(user,'camp_added',user.cadet_id,d.camp_name);send(res,201,{id:Number(r.lastInsertRowid)})});
R('PUT','/api/me/camps/:id',['CADET'],async({req,user,params})=>{const d=campData(await jsonBody(req));
  const r=run(`UPDATE camps SET ${CK.map(k=>k+'=?').join(',')},updated_at=datetime('now') WHERE id=? AND user_id=?`,...CK.map(k=>d[k]),int(params.id),user.id);if(!r.changes)throw bad('Not found',404);audit(user,'camp_updated',user.cadet_id,d.camp_name);return {ok:true}});
R('DELETE','/api/me/camps/:id',['CADET'],({user,params})=>{if(!run('DELETE FROM camps WHERE id=? AND user_id=?',int(params.id),user.id).changes)throw bad('Not found',404);audit(user,'camp_deleted',user.cadet_id,params.id);return {ok:true}});
const CF='id,camp_id,certificate_type,file_name,file_size,mime_type,uploaded_at';
R('GET','/api/me/certificates',['CADET'],({user})=>q(`SELECT ${CF} FROM certificates WHERE user_id=? ORDER BY id DESC`,user.id));
R('POST','/api/me/certificates',['CADET'],async({req,res,user})=>{
  const m=multipart(await readBody(req,MAX+65536,'Certificate must be less than 5 MB'),req.headers['content-type']),f=m.file;
  if(!f||!f.data.length)throw bad('Please choose a file');if(f.data.length>MAX)throw bad('Certificate must be less than 5 MB',413);
  const kind=sniff(f.data),ext=f.name.split('.').pop().toLowerCase();if(!kind||({pdf:'pdf',jpg:'jpg',jpeg:'jpg',png:'png'})[ext]!==kind.ext)throw bad('Only PDF, JPG, JPEG or PNG files are allowed');
  const type=S(m.fields.certificate_type);if(!META.CERT_TYPES.includes(type))throw bad('Choose a certificate type');
  let camp=null;if(m.fields.camp_id){camp=q1('SELECT id FROM camps WHERE id=? AND user_id=?',int(m.fields.camp_id),user.id);if(!camp)throw bad('Invalid camp')}
  if(q1('SELECT COUNT(*) n FROM certificates WHERE user_id=?',user.id).n>=30)throw bad('Certificate limit reached');
  const stored=crypto.randomBytes(20).toString('hex')+'.'+kind.ext;fs.writeFileSync(path.join(CERTS,stored),f.data,{mode:0o600});
  const r=run('INSERT INTO certificates(user_id,camp_id,certificate_type,file_name,stored_name,file_size,mime_type) VALUES(?,?,?,?,?,?,?)',user.id,camp?camp.id:null,type,f.name,stored,f.data.length,kind.mime);
  audit(user,'certificate_uploaded',user.cadet_id,f.name);send(res,201,{id:Number(r.lastInsertRowid)})});
R('DELETE','/api/me/certificates/:id',['CADET'],({user,params})=>{const c=q1('SELECT * FROM certificates WHERE id=? AND user_id=?',int(params.id),user.id);if(!c)throw bad('Not found',404);
  run('DELETE FROM certificates WHERE id=?',c.id);fs.unlink(path.join(CERTS,path.basename(c.stored_name)),()=>{});audit(user,'certificate_deleted',user.cadet_id,c.file_name);return {ok:true}});
// certificate file: owner, ANO of the cadet's unit, or super admin. Not a public URL; checked on every request.
R('GET','/api/certificates/:id/file',[],({res,user,params,url})=>{
  const c=q1('SELECT c.*,u.unit_id,u.cadet_id cid FROM certificates c JOIN users u ON u.id=c.user_id WHERE c.id=?',int(params.id));
  if(!c||!(user.id===c.user_id||user.role==='SUPER_ADMIN'||(user.role==='ANO'&&user.unit_id!=null&&user.unit_id===c.unit_id)))throw bad('Not found',404);
  if(user.id!==c.user_id)audit(user,url.searchParams.get('download')?'certificate_downloaded':'certificate_viewed',c.cid,c.file_name);
  res.writeHead(200,{'Content-Type':c.mime_type,'Content-Length':c.file_size,'Content-Disposition':`${url.searchParams.get('download')?'attachment':'inline'}; filename*=UTF-8''${encodeURIComponent(c.file_name)}`,'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});
  fs.createReadStream(path.join(CERTS,path.basename(c.stored_name))).pipe(res)});
// ----- ANO / super admin -----
R('GET','/api/ano/cadets',ANO,({user})=>scoped(user).map(summary));
R('GET','/api/ano/cadets/:id',ANO,({user,params})=>{const c=authorizedCadet(user,params.id);audit(user,'cadet_viewed',c.cadet_id,'profile');
  return {...summary(c),camps:q('SELECT * FROM camps WHERE user_id=? ORDER BY from_date DESC',c.id),certs:q(`SELECT ${CF} FROM certificates WHERE user_id=? ORDER BY id DESC`,c.id)}});
R('GET','/api/ano/stats',ANO,({user})=>{const list=scoped(user).map(summary),ids=list.map(c=>c.id),cnt=(arr,f)=>arr.reduce((a,x)=>{const k=f(x)||'—';a[k]=(a[k]||0)+1;return a},{});
  const certs=ids.length?q(`SELECT certificate_type t FROM certificates WHERE user_id IN (${ids.map(()=>'?')})`,...ids):[];
  return {cadets:list.length,active:list.filter(c=>c.active).length,camps:list.reduce((a,c)=>a+c.camps,0),certificates:certs.length,completed:list.filter(c=>c.completion>=100).length,
   avgCompletion:list.length?Math.round(list.reduce((a,c)=>a+c.completion,0)/list.length):0,byYear:cnt(list,c=>c.year?'Year '+c.year:'Not set'),campsByType:cnt(list.flatMap(c=>c.camp_types),x=>x),certsByType:cnt(certs,x=>x.t),
   completion:cnt(list,c=>c.completion>=100?'100%':c.completion>=75?'75-99%':c.completion>=50?'50-74%':'Below 50%'),changed:user.prev_login?list.filter(c=>c.updated_at>user.prev_login).length:0}});
R('GET','/api/ano/export',ANO,({res,user,url})=>{let list=scoped(user).map(summary);const ids=url.searchParams.get('ids');if(ids){const s=new Set(ids.split(',').map(Number));list=list.filter(c=>s.has(c.id))}
  const fmt=url.searchParams.get('format')==='csv'?'csv':'xlsx',rows=[['Cadet ID','Name','Student ID','DOB','Gender','College','Branch','Year','Phone','Email','NCC Unit','Battalion','Wing','Enrollment No','NCC Rank','Enrollment Date','NCC Year','ANO','Camps','Camp Names','Certificates','Profile %','Last Updated'],
   ...list.map(c=>[c.cadet_id,c.full_name,c.student_id,c.dob,c.gender,c.college,c.department,c.year,c.phone,c.email,c.ncc_unit,c.battalion,c.wing,c.enrollment_number,c.ncc_rank,c.enrollment_date,c.current_ncc_year,c.ano_name,c.camps,c.camp_names.join('; '),c.certificates,c.completion,c.updated_at].map(safe))];
  audit(user,'export_generated',fmt,list.length+' cadets');const body=fmt==='csv'?Buffer.from('\ufeff'+csv(rows)):xlsx(rows);
  res.writeHead(200,{'Content-Type':fmt==='csv'?'text/csv; charset=utf-8':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':`attachment; filename="CADET_INFO_export.${fmt}"`,'Cache-Control':'no-store'});res.end(body)});
// ----- super admin -----
const SA=['SUPER_ADMIN'];
R('POST','/api/admin/units',SA,async({req,user,res})=>{const b=await jsonBody(req),n=S(b.unit_name,120),bt=S(b.battalion,120),i=S(b.institution,150);if(!n||!bt||!i)throw bad('All fields are required');
  try{const r=run('INSERT INTO units(unit_name,battalion,institution) VALUES(?,?,?)',n,bt,i);audit(user,'unit_created',n);send(res,201,{id:Number(r.lastInsertRowid)})}catch(e){if(/UNIQUE/.test(e.message))throw bad('Unit already exists',409);throw e}});
R('GET','/api/admin/anos',SA,()=>q("SELECT u.id,u.name,u.email,u.ano_id,u.active,u.last_login,un.unit_name FROM users u LEFT JOIN units un ON un.id=u.unit_id WHERE u.role='ANO' ORDER BY u.name"));
R('POST','/api/admin/anos',SA,async({req,user,res})=>{const b=await jsonBody(req),name=S(b.name,120),email=S(b.email,120).toLowerCase(),aid=S(b.ano_id,30),pw=String(b.password||''),unit=q1('SELECT id FROM units WHERE id=?',int(b.unit_id));
  if(!name||!/^[A-Za-z0-9._-]{3,30}$/.test(aid)||!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email))throw bad('Name, valid ANO ID and email are required');if(pw.length<10)throw bad('Password must be at least 10 characters');if(!unit)throw bad('Choose a unit');
  try{const id=addUser({name,email,password:pw,role:'ANO',ano_id:aid,unit_id:unit.id});audit(user,'ano_created',aid);send(res,201,{id})}catch(e){if(/UNIQUE/.test(e.message))throw bad('ANO ID or email already exists',409);throw e}});
R('PATCH','/api/admin/users/:id/active',SA,async({req,user,params})=>{const b=await jsonBody(req),id=int(params.id);if(id===user.id)throw bad('You cannot deactivate yourself');
  if(!run('UPDATE users SET active=? WHERE id=?',b.active?1:0,id).changes)throw bad('Not found',404);if(!b.active)run('DELETE FROM sessions WHERE user_id=?',id);audit(user,b.active?'user_activated':'user_deactivated',id);return {ok:true}});
R('GET','/api/admin/audit',SA,()=>q('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300'));
// ---------- HTTP ----------
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'};
function secHeaders(res){res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');if(PROD)res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains')}
function serveStatic(req,res,p){if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405);return res.end()}
  let f=path.normalize(path.join(PUB,p==='/'?'index.html':p));if(!f.startsWith(PUB+path.sep)||!fs.existsSync(f)||!fs.statSync(f).isFile())f=path.join(PUB,'index.html');
  res.writeHead(200,{'Content-Type':MIME[path.extname(f)]||'application/octet-stream','Cache-Control':'no-cache'});fs.createReadStream(f).pipe(res)}
async function handle(req,res){const url=new URL(req.url,'http://x'),p=url.pathname;secHeaders(res);if(!p.startsWith('/api/'))return serveStatic(req,res,p);
  try{const user=getUser(req);if(req.method!=='GET'&&req.headers['x-requested-with']!=='cadetinfo')throw bad('Forbidden',403);
    const r=routes.find(r=>r.m===req.method&&r.re.test(p));if(!r)throw bad('Not found',404);
    if(r.roles){if(!user)throw bad('Please log in',401);if(r.roles.length&&!r.roles.includes(user.role))throw bad('Forbidden',403)}
    const out=await r.fn({req,res,user,params:r.re.exec(p).groups||{},url});if(out!==undefined&&!res.writableEnded)send(res,200,out)}
  catch(e){if(res.headersSent){return res.end()}if(e instanceof HttpError)send(res,e.status,{error:e.message});else{console.error(e);send(res,500,{error:'Server error'})}}}
function ensureSuperAdmin(){const e=process.env.SUPERADMIN_EMAIL,p=process.env.SUPERADMIN_PASSWORD;if(e&&p&&!q1('SELECT id FROM users WHERE email=?',e))addUser({name:'Super Admin',email:e,password:p,role:'SUPER_ADMIN',ano_id:'SUPERADMIN'})}
function start(port=+process.env.PORT||3000){ensureSuperAdmin();return http.createServer(handle).listen(port,()=>console.log('CADET INFO running on port',port))}
module.exports={start,db,addUser,META};
if(require.main===module)start();
