const express = require("express");
const multer = require("multer");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, "data");
const UPLOADS = path.join(DATA, "scripts");
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new Database(path.join(DATA, "app.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS scripts (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, filename TEXT NOT NULL,
 mode TEXT NOT NULL CHECK(mode IN ('public','key-device','key')),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
 id INTEGER PRIMARY KEY AUTOINCREMENT, script_id TEXT NOT NULL,
 key TEXT UNIQUE NOT NULL, device_id TEXT, expires_at TEXT,
 revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
`);

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,"public")));

const upload=multer({
 dest:path.join(DATA,"tmp"),
 limits:{fileSize:2*1024*1024},
 fileFilter:(req,file,cb)=>cb(null,path.extname(file.originalname).toLowerCase()===".lua")
});


function protectLua(source){
  let out="", quote=null, esc=false, lineComment=false, blockComment=false;
  for(let i=0;i<source.length;i++){
    const c=source[i], n=source[i+1];
    if(lineComment){ if(c==="\\n"){lineComment=false; out+="\\n";} continue; }
    if(blockComment){ if(c==="*" && n==="]"){blockComment=false;i++;} continue; }
    if(!quote && c==="-" && n==="-"){
      if(source[i+2]==="[" && source[i+3]==="["){blockComment=true;i+=3;continue;}
      lineComment=true;i++;continue;
    }
    if(quote){
      out+=c;
      if(esc){esc=false;continue;}
      if(c==="\\\\"){esc=true;continue;}
      if(c===quote)quote=null;
      continue;
    }
    if(c==="\"" || c==="'"){quote=c;out+=c;continue;}
    if(/\s/.test(c)){ if(out && !/\s$/.test(out)) out+=" "; }
    else out+=c;
  }
  return out.trim();
}

function id(n=6){return crypto.randomBytes(n).toString("hex")}
function key(){return "KEY-"+crypto.randomBytes(6).toString("hex").toUpperCase()}
function now(){return new Date().toISOString()}

app.get("/api/scripts",(req,res)=>{
 res.json(db.prepare("SELECT id,name,mode,created_at FROM scripts ORDER BY created_at DESC").all());
});

app.post("/api/scripts",upload.single("file"),(req,res)=>{
 if(!req.file)return res.status(400).json({error:"Upload a .lua file."});
 const mode=["public","key-device","key"].includes(req.body.mode)?req.body.mode:"public";
 const scriptId=id();
 const filename=scriptId+".lua";
 const original=fs.readFileSync(req.file.path,"utf8");
  fs.unlinkSync(req.file.path);
  fs.writeFileSync(path.join(UPLOADS,filename),protectLua(original),"utf8");
 db.prepare("INSERT INTO scripts VALUES(?,?,?,?,?)")
   .run(scriptId,req.body.name||req.file.originalname,filename,mode,now());
 res.json({
   ok:true,scriptId,mode,
   loader:`loadstring(game:HttpGet("${req.protocol}://${req.get("host")}/l/${scriptId}"))()`
 });
});

app.post("/api/keys",(req,res)=>{
 const script=db.prepare("SELECT * FROM scripts WHERE id=?").get(req.body.script_id);
 if(!script)return res.status(404).json({error:"Script not found"});
 const count=Math.min(Math.max(Number(req.body.count)||1,1),50);
 const stmt=db.prepare("INSERT INTO keys(script_id,key,expires_at,created_at) VALUES(?,?,?,?)");
 const keys=[];
 for(let i=0;i<count;i++){const k=key();stmt.run(script.id,k,req.body.expires_at||null,now());keys.push(k)}
 res.json({keys});
});

app.get("/api/keys/:scriptId",(req,res)=>{
 res.json(db.prepare("SELECT id,key,device_id,expires_at,revoked,created_at FROM keys WHERE script_id=? ORDER BY id DESC").all(req.params.scriptId));
});

app.post("/api/keys/:id/revoke",(req,res)=>{
 db.prepare("UPDATE keys SET revoked=1 WHERE id=?").run(req.params.id);
 res.json({ok:true});
});

app.post("/api/keys/:id/reset-device",(req,res)=>{
 db.prepare("UPDATE keys SET device_id=NULL WHERE id=?").run(req.params.id);
 res.json({ok:true});
});

function validKey(k){
 const row=db.prepare(`SELECT k.*,s.mode,s.id script_id
   FROM keys k JOIN scripts s ON s.id=k.script_id WHERE k.key=?`).get(k);
 if(!row||row.revoked)return null;
 if(row.expires_at&&new Date(row.expires_at)<=new Date())return null;
 return row;
}

app.post("/api/authorize",(req,res)=>{
 const script=db.prepare("SELECT * FROM scripts WHERE id=?").get(req.body.script_id);
 if(!script)return res.status(404).json({ok:false,error:"Script not found"});
 if(script.mode==="public")return res.json({ok:true});
 const row=validKey(String(req.body.key||"").trim());
 if(!row||row.script_id!==script.id)return res.status(403).json({ok:false,error:"Invalid key"});
 const device=String(req.body.device_id||"").trim();
 if(script.mode==="key-device"){
   if(!device)return res.status(400).json({ok:false,error:"Device ID required"});
   if(!row.device_id)db.prepare("UPDATE keys SET device_id=? WHERE id=?").run(device,row.id);
   else if(row.device_id!==device)return res.status(403).json({ok:false,error:"Key is already bound to another device"});
 }
 res.json({ok:true});
});

app.get("/l/:id",(req,res)=>{
 const script=db.prepare("SELECT * FROM scripts WHERE id=?").get(req.params.id);
 if(!script)return res.status(404).send("-- Script not found");
 if(script.mode!=="public")return res.status(403).send("-- Protected loader requires authorization");
 const file=path.join(UPLOADS,script.filename);
 if(!fs.existsSync(file))return res.status(404).send("-- File missing");
 res.type("text/plain").send(fs.readFileSync(file,"utf8"));
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Loader Studio on port ${PORT}`));
