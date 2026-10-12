// Demo data. Passwords are random (printed once) unless SEED_PASSWORD is set. Never use in production.
const crypto=require('crypto'),{db,addUser}=require('./server');
if(db.prepare('SELECT COUNT(*) n FROM units').get().n){console.log('Database already has data; seed skipped.');process.exit(0)}
const pw=()=>process.env.SEED_PASSWORD||crypto.randomBytes(9).toString('base64url');
db.exec("INSERT INTO units(unit_name,battalion,institution) VALUES('1 (A) Engineering Coy','5 Telangana Bn NCC','Demo Engineering College'),('2 (B) Arts Coy','6 Telangana Bn NCC','Demo Arts College')");
const rows=[['SUPER_ADMIN','Super Admin','superadmin@cadetinfo.local','SUPERADMIN',null],['ANO','Lt. Rao (Unit A)','ano.a@cadetinfo.local','ANO-A',1],['ANO','Capt. Devi (Unit B)','ano.b@cadetinfo.local','ANO-B',2],
 ['CADET','Demo Cadet One','cadet1@cadetinfo.local','C-1001',1],['CADET','Demo Cadet Two','cadet2@cadetinfo.local','C-1002',1],['CADET','Demo Cadet Three','cadet3@cadetinfo.local','C-2001',2]];
console.log('\nLogin ID'.padEnd(18)+'Portal'.padEnd(14)+'Password');
for(const [role,name,email,id,unit] of rows){const p=pw();addUser({name,email,password:p,role,cadet_id:role==='CADET'?id:null,ano_id:role!=='CADET'?id:null,unit_id:unit});console.log(id.padEnd(18)+(role==='CADET'?'Cadet':'ANO/Admin').padEnd(14)+p)}
const c1=db.prepare("SELECT id FROM users WHERE cadet_id='C-1001'").get().id;
db.prepare("INSERT INTO camps(user_id,camp_name,camp_type,location,from_date,to_date,number_of_days,organizing_unit,status,experience) VALUES(?,?,?,?,?,?,?,?,?,?)").run(c1,'Combined Annual Training Camp','CATC','Hyderabad','2026-01-05','2026-01-14',9,'5 Telangana Bn','Completed','Drill, weapon training and team leadership.');
console.log('\nDemo only — change or delete these accounts before real use.\n');
