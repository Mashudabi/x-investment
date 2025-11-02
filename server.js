/****
 X Investment - Minimal real backend (simulation)
 - Node.js + Express
 - Stores users and payments in JSON files under server/data/
 - Passwords hashed with pbkdf2
 - Simple token-based sessions (in-memory)
 - Simulated mobile payment flow: create -> PENDING -> SUCCESS after a timeout
 IMPORTANT: For production, use HTTPS, proper DB, secure session store, and integrate a real payment provider.
****/

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { nanoid } = require('nanoid');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
fs.ensureDirSync(DATA_DIR);

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PAYMENTS_FILE = path.join(DATA_DIR, 'payments.json');

function loadJson(p){ try{ return fs.readJsonSync(p); }catch(e){ return {}; } }
function saveJson(p, data){ fs.writeJsonSync(p, data, { spaces:2 }); }

let users = loadJson(USERS_FILE); // phone -> user object
let payments = loadJson(PAYMENTS_FILE); // id -> payment

// simple in-memory sessions: token -> phone
const sessions = {};

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// --- helpers ---
function pbkdf2Hash(password, salt=null){
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 200000, 64, 'sha256').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash){
  const h = crypto.pbkdf2Sync(password, salt, 200000, 64, 'sha256').toString('hex');
  return h === hash;
}

function saveAll(){
  saveJson(USERS_FILE, users);
  saveJson(PAYMENTS_FILE, payments);
}

// --- API ---

// POST /api/signup { name, phone, password }
app.post('/api/signup', (req, res) => {
  const { name, phone, password } = req.body;
  if(!name || !phone || !password) return res.status(400).json({ error:'missing fields' });
  if(users[phone]) return res.status(400).json({ error:'account exists' });
  const { salt, hash } = pbkdf2Hash(password);
  const user = {
    phone, name, salt, passHash: hash,
    balance: 0,
    txs: [],
    picture: null,
    createdAt: new Date().toISOString()
  };
  users[phone] = user;
  saveAll();
  const token = nanoid(24);
  sessions[token] = phone;
  return res.json({ token });
});

// POST /api/login { phone, password }
app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  if(!phone || !password) return res.status(400).json({ error:'missing fields' });
  const user = users[phone];
  if(!user) return res.status(404).json({ error:'account not found' });
  if(!verifyPassword(password, user.salt, user.passHash)) return res.status(403).json({ error:'invalid password' });
  const token = nanoid(24);
  sessions[token] = phone;
  return res.json({ token, user: { name:user.name, phone:user.phone, balance:user.balance } });
});

// GET /api/user/:phone
app.get('/api/user/:phone', (req, res) => {
  const phone = req.params.phone;
  const user = users[phone];
  if(!user) return res.status(404).json({ error:'not found' });
  // return public view
  return res.json({ user: { name:user.name, phone:user.phone, balance:user.balance, txs:user.txs, picture:user.picture } });
});

// POST /api/user/picture { phone, picture }
app.post('/api/user/picture', (req, res) => {
  const { phone, picture } = req.body;
  if(!phone || !picture) return res.status(400).json({ error:'missing fields' });
  const user = users[phone];
  if(!user) return res.status(404).json({ error:'no user' });
  user.picture = picture;
  saveAll();
  return res.json({ ok:true });
});

// POST /api/deposit { phone, amount }
app.post('/api/deposit', (req, res) => {
  const { phone, amount } = req.body;
  if(!phone || !amount) return res.status(400).json({ error:'missing' });
  const user = users[phone];
  if(!user) return res.status(404).json({ error:'no user' });
  const a = Number(amount);
  if(isNaN(a) || a<=0) return res.status(400).json({ error:'invalid amount' });
  user.balance = Number(user.balance || 0) + a;
  const tx = { id:'tx_'+nanoid(8), type:'deposit', amount:a, createdAt:new Date().toISOString(), meta:{ note:'Manual deposit' } };
  user.txs.push(tx);
  saveAll();
  return res.json({ ok:true, balance:user.balance });
});

// POST /api/withdraw { phone, amount }
app.post('/api/withdraw', (req, res) => {
  const { phone, amount } = req.body;
  if(!phone || !amount) return res.status(400).json({ error:'missing' });
  const user = users[phone];
  if(!user) return res.status(404).json({ error:'no user' });
  const a = Number(amount);
  if(isNaN(a) || a<=0) return res.status(400).json({ error:'invalid amount' });
  if(a > user.balance) return res.status(400).json({ error:'insufficient balance' });
  user.balance = Number(user.balance || 0) - a;
  const tx = { id:'tx_'+nanoid(8), type:'withdraw', amount:a, createdAt:new Date().toISOString(), meta:{ note:'Manual withdrawal' } };
  user.txs.push(tx);
  saveAll();
  return res.json({ ok:true, balance:user.balance });
});

// POST /api/logout { phone }
app.post('/api/logout', (req, res) => {
  // remove sessions matching phone
  const { phone } = req.body;
  for(const t in sessions){ if(sessions[t] === phone) delete sessions[t]; }
  return res.json({ ok:true });
});

// Payment simulation
// POST /api/payment/create { phone (investor), amount, payTo (mobile) }
app.post('/api/payment/create', (req, res) => {
  const { phone, amount, payTo } = req.body;
  if(!phone || !amount || !payTo) return res.status(400).json({ error:'missing' });
  const user = users[phone];
  if(!user) return res.status(404).json({ error:'no user' });
  const a = Number(amount);
  if(isNaN(a) || a < 250) return res.status(400).json({ error:'invalid amount, minimum 250' });
  const id = nanoid(12);
  const payment = { id, phone, payTo, amount:a, status:'PENDING', createdAt:new Date().toISOString() };
  payments[id] = payment;
  saveAll();
  // simulate async payment result after 8-12 seconds
  setTimeout(()=>{
    // 85% chance success
    const ok = Math.random() < 0.85;
    if(ok){
      payment.status = 'SUCCESS';
      // credit 10% bonus
      const credited = Math.round((a * 1.10) * 100) / 100;
      user.balance = Number(user.balance || 0) + credited;
      const tx = { id:'tx_'+nanoid(8), type:'invest', amount:credited, createdAt:new Date().toISOString(), meta:{ principal:a, bonus: credited - a } };
      user.txs.push(tx);
      saveAll();
    } else {
      payment.status = 'FAILED';
      saveAll();
    }
  }, 9000 + Math.floor(Math.random()*3000));
  return res.json({ ok:true, paymentId:id });
});

// GET /api/payment/status/:id
app.get('/api/payment/status/:id', (req, res) => {
  const id = req.params.id;
  const p = payments[id];
  if(!p) return res.status(404).json({ error:'not found' });
  return res.json({ status: p.status, note: p.status === 'SUCCESS' ? 'Payment received and investment credited.' : undefined });
});

// POST /api/payment/cancel/:id
app.post('/api/payment/cancel/:id', (req, res) => {
  const id = req.params.id;
  const p = payments[id];
  if(!p) return res.status(404).json({ error:'not found' });
  if(p.status === 'PENDING'){ p.status = 'CANCELLED'; saveAll(); return res.json({ ok:true }); }
  return res.status(400).json({ error:'cannot cancel' });
});

// start server
const port = process.env.PORT || 3000;
app.listen(port, ()=>{ console.log('X Investment server running on port', port); });
