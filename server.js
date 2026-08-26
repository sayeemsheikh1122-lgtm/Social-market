
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
app.use(cors({origin:"*"}));
app.use(express.json({limit:"1mb"}));

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-render";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";

const db = new Database(process.env.DB_PATH || "markethub.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 username TEXT UNIQUE NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 balance REAL NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS listings(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 title TEXT NOT NULL,
 category TEXT NOT NULL,
 description TEXT,
 price REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 listing_id INTEGER,
 type TEXT NOT NULL,
 item TEXT NOT NULL,
 amount REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS services(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 type TEXT NOT NULL,
 platform TEXT NOT NULL,
 quantity TEXT,
 target TEXT,
 amount REAL NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function ensureAdmin(){
  const row = db.prepare("SELECT id FROM users WHERE username=?").get(ADMIN_USER);
  if(!row){
    const hash = bcrypt.hashSync(ADMIN_PASS, 10);
    db.prepare("INSERT INTO users(name,username,email,password,role) VALUES(?,?,?,?,?)")
      .run("Administrator", ADMIN_USER, "admin@markethub.local", hash, "admin");
  }
}
ensureAdmin();

function tokenFor(user){ return jwt.sign({id:user.id, role:user.role, username:user.username}, JWT_SECRET, {expiresIn:"7d"}); }

function auth(req,res,next){
  try{
    const h = req.headers.authorization || "";
    if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Authentication required"});
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  }catch(e){ return res.status(401).json({error:"Invalid or expired token"}); }
}
function admin(req,res,next){
  if(req.user?.role !== "admin") return res.status(403).json({error:"Admin only"});
  next();
}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"MarketHub API"}));

app.post("/api/auth/register", async (req,res)=>{
  const {name,username,email,password}=req.body||{};
  if(!name||!username||!email||!password) return res.status(400).json({error:"All fields are required"});
  if(password.length < 6) return res.status(400).json({error:"Password must be at least 6 characters"});
  try{
    const hash = await bcrypt.hash(password,10);
    const info = db.prepare("INSERT INTO users(name,username,email,password) VALUES(?,?,?,?)")
      .run(name.trim(),username.trim(),email.trim().toLowerCase(),hash);
    const user = db.prepare("SELECT id,name,username,email,role,balance,created_at FROM users WHERE id=?").get(info.lastInsertRowid);
    res.status(201).json({user,token:tokenFor(user)});
  }catch(e){ res.status(409).json({error:"Username or email already exists"}); }
});

app.post("/api/auth/login", async (req,res)=>{
  const {username,password}=req.body||{};
  const user=db.prepare("SELECT * FROM users WHERE username=?").get(username||"");
  if(!user || !(await bcrypt.compare(password||"",user.password))) return res.status(401).json({error:"Invalid username or password"});
  const safe={id:user.id,name:user.name,username:user.username,email:user.email,role:user.role,balance:user.balance,created_at:user.created_at};
  res.json({user:safe,token:tokenFor(user)});
});

app.get("/api/me",auth,(req,res)=>{
  const u=db.prepare("SELECT id,name,username,email,role,balance,created_at FROM users WHERE id=?").get(req.user.id);
  res.json({user:u});
});

app.get("/api/listings",(req,res)=>{
  const rows=db.prepare(`
    SELECT l.*,u.username AS seller
    FROM listings l JOIN users u ON u.id=l.user_id
    WHERE l.status='approved' ORDER BY l.id DESC
  `).all();
  res.json({listings:rows});
});

app.post("/api/listings",auth,(req,res)=>{
  const {title,category,description,price}=req.body||{};
  if(!title||!category||price===undefined) return res.status(400).json({error:"title, category and price required"});
  const p=Number(price);
  if(!Number.isFinite(p)||p<0) return res.status(400).json({error:"Invalid price"});
  const info=db.prepare("INSERT INTO listings(user_id,title,category,description,price) VALUES(?,?,?,?,?)")
    .run(req.user.id,title,category,description||"",p);
  res.status(201).json({id:info.lastInsertRowid,status:"pending"});
});

app.get("/api/my/listings",auth,(req,res)=>{
  res.json({listings:db.prepare("SELECT * FROM listings WHERE user_id=? ORDER BY id DESC").all(req.user.id)});
});

app.post("/api/orders",auth,(req,res)=>{
  const {listingId}=req.body||{};
  const listing=db.prepare("SELECT * FROM listings WHERE id=? AND status='approved'").get(listingId);
  if(!listing) return res.status(404).json({error:"Listing not found"});
  if(listing.user_id===req.user.id) return res.status(400).json({error:"You cannot order your own listing"});
  const buyer=db.prepare("SELECT balance FROM users WHERE id=?").get(req.user.id);
  if(buyer.balance < listing.price) return res.status(400).json({error:"Insufficient demo wallet balance"});
  const tx=db.transaction(()=>{
    db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(listing.price,req.user.id);
    db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(listing.price,listing.user_id);
    return db.prepare("INSERT INTO orders(user_id,listing_id,type,item,amount,status) VALUES(?,?,?,?,?,?)")
      .run(req.user.id,listing.id,"listing",listing.title,listing.price,"completed");
  });
  const info=tx();
  res.status(201).json({orderId:info.lastInsertRowid,status:"completed"});
});

app.get("/api/my/orders",auth,(req,res)=>{
  res.json({orders:db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.user.id)});
});

app.post("/api/services",auth,(req,res)=>{
  const {type,platform,quantity,target,amount}=req.body||{};
  if(!type||!platform||!target) return res.status(400).json({error:"type, platform and target required"});
  const a=Number(amount||0);
  if(!Number.isFinite(a)||a<0) return res.status(400).json({error:"Invalid amount"});
  const info=db.prepare("INSERT INTO services(user_id,type,platform,quantity,target,amount) VALUES(?,?,?,?,?,?)")
    .run(req.user.id,type,platform,quantity||"",target,a);
  res.status(201).json({id:info.lastInsertRowid,status:"pending"});
});

app.get("/api/my/services",auth,(req,res)=>{
  res.json({services:db.prepare("SELECT * FROM services WHERE user_id=? ORDER BY id DESC").all(req.user.id)});
});

app.get("/api/admin/stats",auth,admin,(req,res)=>{
  res.json({
    users:db.prepare("SELECT COUNT(*) c FROM users WHERE role='user'").get().c,
    listings:db.prepare("SELECT COUNT(*) c FROM listings").get().c,
    pendingListings:db.prepare("SELECT COUNT(*) c FROM listings WHERE status='pending'").get().c,
    orders:db.prepare("SELECT COUNT(*) c FROM orders").get().c,
    services:db.prepare("SELECT COUNT(*) c FROM services").get().c
  });
});

app.get("/api/admin/users",auth,admin,(req,res)=>{
  res.json({users:db.prepare("SELECT id,name,username,email,role,balance,created_at FROM users ORDER BY id DESC").all()});
});

app.get("/api/admin/listings",auth,admin,(req,res)=>{
  res.json({listings:db.prepare("SELECT l.*,u.username seller FROM listings l JOIN users u ON u.id=l.user_id ORDER BY l.id DESC").all()});
});

app.patch("/api/admin/listings/:id",auth,admin,(req,res)=>{
  const status=req.body?.status;
  if(!["pending","approved","rejected"].includes(status)) return res.status(400).json({error:"Invalid status"});
  db.prepare("UPDATE listings SET status=? WHERE id=?").run(status,req.params.id);
  res.json({ok:true});
});

app.get("/api/admin/orders",auth,admin,(req,res)=>{
  res.json({orders:db.prepare("SELECT o.*,u.username FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC").all()});
});

app.get("/api/admin/services",auth,admin,(req,res)=>{
  res.json({services:db.prepare("SELECT s.*,u.username FROM services s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC").all()});
});

app.patch("/api/admin/services/:id",auth,admin,(req,res)=>{
  const status=req.body?.status;
  if(!["pending","approved","rejected","completed"].includes(status)) return res.status(400).json({error:"Invalid status"});
  db.prepare("UPDATE services SET status=? WHERE id=?").run(status,req.params.id);
  res.json({ok:true});
});

app.post("/api/admin/users/:id/balance",auth,admin,(req,res)=>{
  const amount=Number(req.body?.amount);
  if(!Number.isFinite(amount)) return res.status(400).json({error:"Invalid amount"});
  db.prepare("UPDATE users SET balance=balance+? WHERE id=? AND role='user'").run(amount,req.params.id);
  res.json({ok:true});
});

app.listen(PORT,()=>console.log(`MarketHub API listening on ${PORT}`));
