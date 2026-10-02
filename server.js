require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes('sslmode=require') ? { rejectUnauthorized: false } : undefined });

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(x=>x.trim()) : true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const clean = v => typeof v === 'string' ? v.trim() : (v ?? '');
function tokenFor(user){ return jwt.sign({id:user.id, username:user.username, role:user.role}, JWT_SECRET, {expiresIn:'12h'}); }
function auth(req,res,next){
  const h=req.headers.authorization||'';
  if(!h.startsWith('Bearer ')) return res.status(401).json({error:'AUTH_REQUIRED'});
  try { req.user=jwt.verify(h.slice(7), JWT_SECRET); next(); } catch { return res.status(401).json({error:'INVALID_TOKEN'}); }
}
function masterOnly(req,res,next){ if(req.user.role!=='master') return res.status(403).json({error:'MASTER_ONLY'}); next(); }
function safeUser(r){ return {id:r.id,username:r.username,role:r.role,balance:Number(r.balance),active:r.active,createdAt:r.created_at}; }
function safeK(r){ return {id:r.id,khatianNo:r.khatian_no,district:r.district,upazila:r.upazila,mouza:r.mouza,jlNo:r.jl_no,recordType:r.record_type,owner:r.owner,guardian:r.guardian,dag:r.dag,landClass:r.land_class,landAmount:r.land_amount,address:r.address,remarks:r.remarks,createdBy:r.created_by_username,createdById:r.created_by,createdAt:r.created_at,updatedAt:r.updated_at}; }

app.get('/api/health', async (req,res)=>{ try { await pool.query('SELECT 1'); res.json({ok:true}); } catch(e){ res.status(503).json({ok:false,error:'DATABASE_UNAVAILABLE'}); }});

app.post('/api/auth/login', async (req,res)=>{
  const username=clean(req.body.username), password=String(req.body.password||'');
  if(!username||!password) return res.status(400).json({error:'USERNAME_PASSWORD_REQUIRED'});
  const {rows}=await pool.query('SELECT * FROM users WHERE username=$1 AND active=true',[username]);
  if(!rows[0] || !(await bcrypt.compare(password,rows[0].password_hash))) return res.status(401).json({error:'INVALID_CREDENTIALS'});
  res.json({token:tokenFor(rows[0]),user:safeUser(rows[0])});
});

app.get('/api/me',auth,async(req,res)=>{ const {rows}=await pool.query('SELECT * FROM users WHERE id=$1 AND active=true',[req.user.id]); if(!rows[0]) return res.status(401).json({error:'USER_NOT_FOUND'}); res.json({user:safeUser(rows[0])}); });

app.get('/api/dashboard',auth,async(req,res)=>{
  const total=await pool.query('SELECT COUNT(*)::int AS n FROM khatians');
  const mine=await pool.query('SELECT COUNT(*)::int AS n FROM khatians WHERE created_by=$1',[req.user.id]);
  const u=await pool.query('SELECT balance FROM users WHERE id=$1',[req.user.id]);
  res.json({total:Number(total.rows[0].n),mine:Number(mine.rows[0].n),balance:Number(u.rows[0]?.balance||0)});
});

app.get('/api/khatians',auth,async(req,res)=>{
  const q=clean(req.query.q); const params=[]; let where='';
  if(q){ params.push(`%${q}%`); where='WHERE k.khatian_no ILIKE $1 OR k.owner ILIKE $1 OR COALESCE(k.dag,\'\') ILIKE $1 OR k.district ILIKE $1 OR k.record_type ILIKE $1'; }
  const {rows}=await pool.query(`SELECT k.*,u.username AS created_by_username FROM khatians k JOIN users u ON u.id=k.created_by ${where} ORDER BY k.created_at DESC LIMIT 500`,params);
  res.json({records:rows.map(safeK)});
});

app.post('/api/khatians',auth,async(req,res)=>{
  const b=req.body; if(!clean(b.khatianNo)||!clean(b.district)||!clean(b.owner)) return res.status(400).json({error:'REQUIRED_FIELDS'});
  const id=crypto.randomUUID();
  const vals=[id,clean(b.khatianNo),clean(b.district),clean(b.upazila),clean(b.mouza),clean(b.jlNo),clean(b.recordType)||'বি.আর.এস',clean(b.owner),clean(b.guardian),clean(b.dag),clean(b.landClass)||'ভিটি',clean(b.landAmount),clean(b.address),clean(b.remarks),req.user.id];
  const {rows}=await pool.query(`INSERT INTO khatians(id,khatian_no,district,upazila,mouza,jl_no,record_type,owner,guardian,dag,land_class,land_amount,address,remarks,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,vals);
  const u=await pool.query('SELECT username FROM users WHERE id=$1',[req.user.id]); rows[0].created_by_username=u.rows[0].username; res.status(201).json({record:safeK(rows[0])});
});

app.put('/api/khatians/:id',auth,async(req,res)=>{
  const old=await pool.query('SELECT * FROM khatians WHERE id=$1',[req.params.id]); if(!old.rows[0]) return res.status(404).json({error:'NOT_FOUND'});
  if(req.user.role!=='master' && old.rows[0].created_by!==req.user.id) return res.status(403).json({error:'NOT_ALLOWED'});
  const b=req.body; if(!clean(b.khatianNo)||!clean(b.district)||!clean(b.owner)) return res.status(400).json({error:'REQUIRED_FIELDS'});
  const vals=[clean(b.khatianNo),clean(b.district),clean(b.upazila),clean(b.mouza),clean(b.jlNo),clean(b.recordType)||'বি.আর.এস',clean(b.owner),clean(b.guardian),clean(b.dag),clean(b.landClass)||'ভিটি',clean(b.landAmount),clean(b.address),clean(b.remarks),req.params.id];
  const {rows}=await pool.query(`UPDATE khatians SET khatian_no=$1,district=$2,upazila=$3,mouza=$4,jl_no=$5,record_type=$6,owner=$7,guardian=$8,dag=$9,land_class=$10,land_amount=$11,address=$12,remarks=$13,updated_at=NOW() WHERE id=$14 RETURNING *`,vals);
  const u=await pool.query('SELECT username FROM users WHERE id=$1',[rows[0].created_by]); rows[0].created_by_username=u.rows[0].username; res.json({record:safeK(rows[0])});
});

app.delete('/api/khatians/:id',auth,async(req,res)=>{
  const old=await pool.query('SELECT created_by FROM khatians WHERE id=$1',[req.params.id]); if(!old.rows[0]) return res.status(404).json({error:'NOT_FOUND'});
  if(req.user.role!=='master' && old.rows[0].created_by!==req.user.id) return res.status(403).json({error:'NOT_ALLOWED'});
  await pool.query('DELETE FROM khatians WHERE id=$1',[req.params.id]); res.json({ok:true});
});

app.post('/api/khatians/:id/print-charge',auth,async(req,res)=>{
  const price=Number(process.env.PRINT_PRICE||10); const client=await pool.connect();
  try { await client.query('BEGIN'); const u=await client.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE',[req.user.id]); if(!u.rows[0]) throw Object.assign(new Error('USER_NOT_FOUND'),{status:404}); if(Number(u.rows[0].balance)<price) throw Object.assign(new Error('INSUFFICIENT_BALANCE'),{status:402}); const k=await client.query('SELECT id FROM khatians WHERE id=$1',[req.params.id]); if(!k.rows[0]) throw Object.assign(new Error('NOT_FOUND'),{status:404}); await client.query('UPDATE users SET balance=balance-$1 WHERE id=$2',[price,req.user.id]); await client.query('INSERT INTO wallet_transactions(user_id,type,amount,reference_id,note) VALUES($1,\'print_charge\',$2,$3,$4)',[req.user.id,-price,req.params.id,'Khatian print/download charge']); await client.query('COMMIT'); const b=await client.query('SELECT balance FROM users WHERE id=$1',[req.user.id]); res.json({ok:true,charged:price,balance:Number(b.rows[0].balance)}); } catch(e){ await client.query('ROLLBACK'); res.status(e.status||500).json({error:e.message||'PRINT_CHARGE_FAILED'}); } finally{client.release();}
});

app.post('/api/recharges',auth,async(req,res)=>{ const amount=Number(req.body.amount),txn=clean(req.body.txnId); if(!Number.isFinite(amount)||amount<10||!txn) return res.status(400).json({error:'INVALID_RECHARGE'}); const id=crypto.randomUUID(); const {rows}=await pool.query('INSERT INTO recharge_requests(id,user_id,amount,txn_id) VALUES($1,$2,$3,$4) RETURNING *',[id,req.user.id,amount,txn]); res.status(201).json({request:rows[0]}); });
app.get('/api/recharges',auth,async(req,res)=>{ const {rows}=await pool.query(`SELECT r.*,u.username,rv.username AS reviewer FROM recharge_requests r JOIN users u ON u.id=r.user_id LEFT JOIN users rv ON rv.id=r.reviewed_by WHERE $1='master' OR r.user_id=$2 ORDER BY r.created_at DESC LIMIT 200`,[req.user.role,req.user.id]); res.json({requests:rows}); });
app.post('/api/recharges/:id/review',auth,masterOnly,async(req,res)=>{ const status=req.body.status; if(!['approved','rejected'].includes(status)) return res.status(400).json({error:'INVALID_STATUS'}); const client=await pool.connect(); try{ await client.query('BEGIN'); const r=await client.query('SELECT * FROM recharge_requests WHERE id=$1 FOR UPDATE',[req.params.id]); if(!r.rows[0]) throw Object.assign(new Error('NOT_FOUND'),{status:404}); if(r.rows[0].status!=='pending') throw Object.assign(new Error('ALREADY_REVIEWED'),{status:409}); await client.query('UPDATE recharge_requests SET status=$1,reviewed_by=$2,reviewed_at=NOW() WHERE id=$3',[status,req.user.id,req.params.id]); if(status==='approved'){ await client.query('UPDATE users SET balance=balance+$1 WHERE id=$2',[r.rows[0].amount,r.rows[0].user_id]); await client.query('INSERT INTO wallet_transactions(user_id,type,amount,reference_id,note) VALUES($1,\'recharge\',$2,$3,$4)',[r.rows[0].user_id,r.rows[0].amount,r.rows[0].id,'Approved bKash recharge']); } await client.query('COMMIT'); res.json({ok:true,status}); }catch(e){await client.query('ROLLBACK');res.status(e.status||500).json({error:e.message||'REVIEW_FAILED'});}finally{client.release();} });

app.get('/api/admin/users',auth,masterOnly,async(req,res)=>{const {rows}=await pool.query('SELECT * FROM users ORDER BY role DESC,created_at ASC');res.json({users:rows.map(safeUser)});});
app.post('/api/admin/users',auth,masterOnly,async(req,res)=>{const username=clean(req.body.username),password=String(req.body.password||'');if(!username||password.length<6)return res.status(400).json({error:'PASSWORD_MIN_6'});const hash=await bcrypt.hash(password,12);try{const {rows}=await pool.query('INSERT INTO users(username,password_hash,role) VALUES($1,$2,\'sub\') RETURNING *',[username,hash]);res.status(201).json({user:safeUser(rows[0])});}catch(e){if(e.code==='23505')return res.status(409).json({error:'USERNAME_EXISTS'});throw e;}});
app.delete('/api/admin/users/:id',auth,masterOnly,async(req,res)=>{if(Number(req.params.id)===req.user.id)return res.status(400).json({error:'CANNOT_DELETE_SELF'});const r=await pool.query('UPDATE users SET active=false WHERE id=$1 AND role=\'sub\' RETURNING id',[req.params.id]);if(!r.rows[0])return res.status(404).json({error:'NOT_FOUND'});res.json({ok:true});});

app.get('/api/verify/:id',async(req,res)=>{const {rows}=await pool.query(`SELECT k.*,u.username AS created_by_username FROM khatians k JOIN users u ON u.id=k.created_by WHERE k.id=$1`,[req.params.id]);if(!rows[0])return res.status(404).json({error:'NOT_FOUND'});const r=rows[0];res.json({verified:true,record:{id:r.id,khatianNo:r.khatian_no,district:r.district,upazila:r.upazila,mouza:r.mouza,jlNo:r.jl_no,recordType:r.record_type,owner:r.owner,guardian:r.guardian,dag:r.dag,landClass:r.land_class,landAmount:r.land_amount,address:r.address,remarks:r.remarks,createdAt:r.created_at}});});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

async function init(){
  await pool.query(require('fs').readFileSync(path.join(__dirname,'db/schema.sql'),'utf8'));
  const username=process.env.ADMIN_USERNAME||'admin', password=process.env.ADMIN_PASSWORD;
  if(password){const hash=await bcrypt.hash(password,12);await pool.query(`INSERT INTO users(username,password_hash,role) VALUES($1,$2,'master') ON CONFLICT(username) DO UPDATE SET password_hash=EXCLUDED.password_hash, role='master', active=true`,[username,hash]);}
  app.listen(PORT,()=>console.log(`DLRMS running on http://localhost:${PORT}`));
}
init().catch(e=>{console.error(e);process.exit(1);});
