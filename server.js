// AutoDex FINAL — serveur sans IA, avec estimation de prix à partir de données publiques.
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import { promisify } from "node:util";
import pg from "pg";
const { Pool } = pg;
const scrypt = promisify(crypto.scrypt);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.PORT || 3000;
app.use(express.json({ limit: "200mb" }));
app.set("trust proxy", 1);
app.use(express.static(path.join(__dirname, "public")));

const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false }
}) : null;
const SESSION_DAYS = 30;
const SESSION_COOKIE = "autodex_session";
function cookieValue(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) { const i = part.indexOf("="); if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim()); }
  return "";
}
function hashToken(token) { return crypto.createHash("sha256").update(token).digest("hex"); }
function setSessionCookie(res, token) {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS*24*60*60}`);
}
function clearSessionCookie(res) { res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`); }
async function initDatabase() {
  if (!pool) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS autodex_users (
    id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL, username_key TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, profile_photo TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS autodex_sessions (
    token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES autodex_users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS autodex_cars (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL UNIQUE REFERENCES autodex_users(id) ON DELETE CASCADE,
    cars_json JSONB NOT NULL DEFAULT '[]'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS autodex_friendships (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES autodex_users(id) ON DELETE CASCADE,
    friend_id BIGINT NOT NULL REFERENCES autodex_users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(user_id,friend_id), CHECK(user_id<>friend_id)
  )`);
  await pool.query("ALTER TABLE autodex_users ADD COLUMN IF NOT EXISTS profile_photo TEXT");
  await pool.query("ALTER TABLE autodex_users ADD COLUMN IF NOT EXISTS display_skin TEXT NOT NULL DEFAULT 'bronze'");
  await pool.query("DELETE FROM autodex_sessions WHERE expires_at < NOW()");
}
function dbRequired(res) { if (pool) return false; res.status(503).json({error:"La base de données n'est pas configurée. Ajoute DATABASE_URL dans Render."}); return true; }
async function currentUser(req) {
  if (!pool) return null;
  const token = cookieValue(req, SESSION_COOKIE); if (!token) return null;
  const result = await pool.query(`SELECT u.id, u.username, u.profile_photo FROM autodex_sessions s JOIN autodex_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()`, [hashToken(token)]);
  return result.rows[0] || null;
}
async function requireUser(req,res,next) {
  try { if (dbRequired(res)) return; const user = await currentUser(req); if (!user) return res.status(401).json({error:"Connecte-toi pour accéder à ta collection."}); req.autodexUser=user; next(); }
  catch(e) { console.error(e); res.status(500).json({error:"Erreur du compte. Réessaie."}); }
}
app.post("/api/auth/register", async (req,res) => {
  if (dbRequired(res)) return;
  try {
    const username = String(req.body?.username || "").trim();
    const key = username.toLocaleLowerCase("fr-FR");
    const password = String(req.body?.password || "");
    if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(username)) return res.status(400).json({error:"Le nom doit contenir 3 à 24 caractères : lettres, chiffres, _ ou - uniquement."});
    if (password.length < 8 || password.length > 128) return res.status(400).json({error:"Choisis un mot de passe de 8 caractères minimum."});
    const exists = await pool.query("SELECT 1 FROM autodex_users WHERE username_key=$1",[key]);
    if (exists.rowCount) return res.status(409).json({error:"Ce nom d'utilisateur est déjà utilisé. Choisis-en un autre."});
    const salt=crypto.randomBytes(16).toString("hex"); const derived=await scrypt(password,salt,64);
    const created=await pool.query("INSERT INTO autodex_users(username,username_key,password_salt,password_hash) VALUES($1,$2,$3,$4) RETURNING id,username",[username,key,salt,derived.toString("hex")]);
    const user=created.rows[0]; await pool.query("INSERT INTO autodex_cars(user_id,cars_json) VALUES($1,'[]'::jsonb)",[user.id]);
    const token=crypto.randomBytes(32).toString("hex"); await pool.query("INSERT INTO autodex_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')",[hashToken(token),user.id]);
    setSessionCookie(res,token); res.status(201).json({user:{username:user.username}});
  } catch(e) { if(e.code==="23505") return res.status(409).json({error:"Ce nom d'utilisateur est déjà utilisé."}); console.error(e); res.status(500).json({error:"Impossible de créer le compte pour le moment."}); }
});
app.post("/api/auth/login", async (req,res) => {
  if (dbRequired(res)) return;
  try {
    const username=String(req.body?.username||"").trim(); const password=String(req.body?.password||"");
    const found=await pool.query("SELECT id,username,password_salt,password_hash FROM autodex_users WHERE username_key=$1",[username.toLocaleLowerCase("fr-FR")]);
    if (!found.rowCount) return res.status(401).json({error:"Nom d'utilisateur ou mot de passe incorrect."});
    const user=found.rows[0]; const test=await scrypt(password,user.password_salt,64);
    const expected=Buffer.from(user.password_hash,"hex"); if(expected.length!==test.length||!crypto.timingSafeEqual(expected,test)) return res.status(401).json({error:"Nom d'utilisateur ou mot de passe incorrect."});
    const token=crypto.randomBytes(32).toString("hex"); await pool.query("INSERT INTO autodex_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')",[hashToken(token),user.id]);
    setSessionCookie(res,token); res.json({user:{username:user.username}});
  } catch(e) { console.error(e); res.status(500).json({error:"Impossible de se connecter pour le moment."}); }
});
app.post("/api/auth/logout", async (req,res) => { try { const token=cookieValue(req,SESSION_COOKIE); if(pool&&token) await pool.query("DELETE FROM autodex_sessions WHERE token_hash=$1",[hashToken(token)]); clearSessionCookie(res); res.json({ok:true}); } catch(e) { clearSessionCookie(res); res.json({ok:true}); } });
app.get("/api/auth/me", async (req,res) => { if(dbRequired(res)) return; try { const user=await currentUser(req); res.json({user:user?{username:user.username,profilePhoto:user.profile_photo||null}:null}); } catch(e) { console.error(e); res.status(500).json({error:"Erreur de vérification du compte."}); } });
app.put("/api/profile", requireUser, async (req,res) => {
  try {
    const username=String(req.body?.username||"").trim();
    const key=username.toLocaleLowerCase("fr-FR");
    const profilePhoto=req.body?.profilePhoto===null?null:String(req.body?.profilePhoto||"");
    if(!/^[\p{L}\p{N}_-]{3,24}$/u.test(username)) return res.status(400).json({error:"Le nom doit contenir 3 à 24 caractères : lettres, chiffres, _ ou - uniquement."});
    if(profilePhoto && (!/^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(profilePhoto) || Buffer.byteLength(profilePhoto)>700*1024)) return res.status(400).json({error:"Photo invalide ou trop lourde. Choisis une image plus petite."});
    const duplicate=await pool.query("SELECT id FROM autodex_users WHERE username_key=$1 AND id<>$2",[key,req.autodexUser.id]);
    if(duplicate.rowCount) return res.status(409).json({error:"Ce nom est déjà utilisé. Choisis-en un autre."});
    const result=await pool.query("UPDATE autodex_users SET username=$1,username_key=$2,profile_photo=$3 WHERE id=$4 RETURNING username,profile_photo",[username,key,profilePhoto||null,req.autodexUser.id]);
    res.json({ok:true,user:{username:result.rows[0].username,profilePhoto:result.rows[0].profile_photo||null}});
  } catch(e){console.error(e);if(e?.code==="23505")return res.status(409).json({error:"Ce nom est déjà utilisé. Choisis-en un autre."});res.status(500).json({error:"Impossible d'enregistrer le profil."});}
});
app.get("/api/cars", requireUser, async (req,res) => { try { const r=await pool.query("SELECT cars_json FROM autodex_cars WHERE user_id=$1",[req.autodexUser.id]); res.json({cars:r.rows[0]?.cars_json||[]}); } catch(e) { console.error(e); res.status(500).json({error:"Impossible de charger la collection."}); } });
app.put("/api/cars", requireUser, async (req,res) => { try { const cars=req.body?.cars; if(!Array.isArray(cars)||cars.length>500) return res.status(400).json({error:"Collection invalide (500 voitures maximum)."}); const bytes=Buffer.byteLength(JSON.stringify(cars)); if(bytes>180*1024*1024) return res.status(413).json({error:"Collection trop volumineuse (limite de 180 Mo). Compresse les photos ou réduis leur nombre."}); await pool.query(`INSERT INTO autodex_cars(user_id,cars_json,updated_at) VALUES($1,$2::jsonb,NOW()) ON CONFLICT(user_id) DO UPDATE SET cars_json=EXCLUDED.cars_json,updated_at=NOW()`,[req.autodexUser.id,JSON.stringify(cars)]); res.json({ok:true}); } catch(e) {
  console.error("Save collection failed:", { code: e?.code, message: e?.message, detail: e?.detail });
  if (e?.code === "23503") return res.status(409).json({error:"Erreur de compte : la session ou le compte n'est plus valide. Déconnecte-toi puis reconnecte-toi."});
  if (e?.code === "54000" || e?.code === "54001" || e?.code === "22001" || e?.code === "22P05") return res.status(413).json({error:"La collection ou les photos sont trop volumineuses pour être enregistrées. Les photos ont été compressées ; essaie de retirer ou remplacer une photo très lourde."});
  if (e?.code === "23505") return res.status(409).json({error:"Conflit pendant l'enregistrement. Recharge la page et réessaie."});
  res.status(500).json({error:"Impossible d'enregistrer la collection. Le serveur ou la base de données a refusé la sauvegarde. Consulte les logs Render pour le code d'erreur."});
} });


// Social : recherche par pseudo, demandes d'amis et profils accessibles entre amis acceptés.
app.get("/api/users/search", requireUser, async (req,res) => {
  try {
    const q=String(req.query.q||"").trim(); if(q.length<2)return res.json({users:[]});
    const result=await pool.query(`SELECT u.id,u.username,u.profile_photo AS "profilePhoto",
      CASE WHEN f.status='accepted' THEN 'friend' WHEN f.status='pending' AND f.user_id=$1 THEN 'sent' WHEN f.status='pending' AND f.friend_id=$1 THEN 'incoming' ELSE 'none' END AS relation
      FROM autodex_users u LEFT JOIN autodex_friendships f ON ((f.user_id=$1 AND f.friend_id=u.id) OR (f.friend_id=$1 AND f.user_id=u.id))
      WHERE u.id<>$1 AND u.username ILIKE $2 ORDER BY u.username LIMIT 12`,[req.autodexUser.id,`%${q.replace(/[\\%_]/g,'\\$&')}%`]);
    res.json({users:result.rows});
  } catch(e){console.error(e);res.status(500).json({error:"Recherche impossible pour le moment."});}
});
app.get("/api/friends", requireUser, async (req,res) => {
  try {
    const [friends,incoming,outgoing]=await Promise.all([
      pool.query(`SELECT u.id,u.username,u.profile_photo AS "profilePhoto",f.id AS friendship_id FROM autodex_friendships f JOIN autodex_users u ON u.id=CASE WHEN f.user_id=$1 THEN f.friend_id ELSE f.user_id END WHERE (f.user_id=$1 OR f.friend_id=$1) AND f.status='accepted' ORDER BY u.username`,[req.autodexUser.id]),
      pool.query(`SELECT f.id,u.username,u.profile_photo AS "profilePhoto",f.created_at FROM autodex_friendships f JOIN autodex_users u ON u.id=f.user_id WHERE f.friend_id=$1 AND f.status='pending' ORDER BY f.created_at DESC`,[req.autodexUser.id]),
      pool.query(`SELECT f.id,u.username,u.profile_photo AS "profilePhoto",f.created_at FROM autodex_friendships f JOIN autodex_users u ON u.id=f.friend_id WHERE f.user_id=$1 AND f.status='pending' ORDER BY f.created_at DESC`,[req.autodexUser.id])
    ]);res.json({friends:friends.rows,incoming:incoming.rows,outgoing:outgoing.rows});
  }catch(e){console.error(e);res.status(500).json({error:"Impossible de charger les amis."});}
});
app.post("/api/friends/request", requireUser, async (req,res) => {
  try{
    const username=String(req.body?.username||"").trim();const target=await pool.query("SELECT id,username,profile_photo FROM autodex_users WHERE username_key=$1",[username.toLocaleLowerCase("fr-FR")]);
    if(!target.rowCount)return res.status(404).json({error:"Aucun compte trouvé avec ce pseudo."});const targetId=target.rows[0].id;
    if(String(targetId)===String(req.autodexUser.id))return res.status(400).json({error:"Tu ne peux pas t'ajouter toi-même."});
    const existing=await pool.query("SELECT id,status,user_id,friend_id FROM autodex_friendships WHERE (user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)",[req.autodexUser.id,targetId]);
    if(existing.rowCount){const f=existing.rows[0];if(f.status==='accepted')return res.status(409).json({error:"Vous êtes déjà amis."});if(String(f.friend_id)===String(req.autodexUser.id)){await pool.query("UPDATE autodex_friendships SET status='accepted' WHERE id=$1",[f.id]);return res.json({ok:true,message:"Demande acceptée : vous êtes maintenant amis."});}return res.status(409).json({error:"Une demande est déjà en attente."});}
    await pool.query("INSERT INTO autodex_friendships(user_id,friend_id,status) VALUES($1,$2,'pending')",[req.autodexUser.id,targetId]);res.status(201).json({ok:true,message:`Demande envoyée à ${target.rows[0].username}.`});
  }catch(e){console.error(e);res.status(500).json({error:"Impossible d'envoyer la demande."});}
});
app.post("/api/friends/:id/accept", requireUser, async (req,res) => {
  try{const r=await pool.query("UPDATE autodex_friendships SET status='accepted' WHERE id=$1 AND friend_id=$2 AND status='pending' RETURNING user_id",[req.params.id,req.autodexUser.id]);if(!r.rowCount)return res.status(404).json({error:"Cette demande n'existe plus."});res.json({ok:true});}
  catch(e){console.error(e);res.status(500).json({error:"Impossible d'accepter la demande."});}
});
app.delete("/api/friends/:id", requireUser, async (req,res) => {
  try{const r=await pool.query("DELETE FROM autodex_friendships WHERE id=$1 AND (user_id=$2 OR friend_id=$2) RETURNING id",[req.params.id,req.autodexUser.id]);if(!r.rowCount)return res.status(404).json({error:"Relation introuvable."});res.json({ok:true});}
  catch(e){console.error(e);res.status(500).json({error:"Impossible de supprimer cette relation."});}
});
app.put("/api/profile/skin", requireUser, async (req,res) => {
  try {
    const skin=String(req.body?.displaySkin||"");
    const thresholds={bronze:100000,silver:500000,gold:1000000,platinum:2500000,diamond:5000000,rainbow:10000000,galaxy:20000000,godly:50000000};
    if(!Object.prototype.hasOwnProperty.call(thresholds,skin)) return res.status(400).json({error:"Skin inconnu."});
    const result=await pool.query("SELECT cars_json FROM autodex_cars WHERE user_id=$1",[req.autodexUser.id]);
    const cars=result.rows[0]?.cars_json||[];
    const total=cars.reduce((sum,c)=>{const n=Number(c.price);return c.price!==""&&c.price!==null&&Number.isFinite(n)&&n>0?sum+n:sum;},0);
    if(total<thresholds[skin]) return res.status(403).json({error:"Ce skin est encore verrouillé : la valeur estimée de ta collection est insuffisante."});
    await pool.query("UPDATE autodex_users SET display_skin=$1 WHERE id=$2",[skin,req.autodexUser.id]);
    res.json({ok:true,displaySkin:skin});
  } catch(e) { console.error(e); res.status(500).json({error:"Impossible d'enregistrer le skin équipé."}); }
});
app.get("/api/users/:username/profile", requireUser, async (req,res) => {
  try{const target=await pool.query("SELECT id,username,profile_photo,display_skin FROM autodex_users WHERE username_key=$1",[String(req.params.username).toLocaleLowerCase("fr-FR")]);if(!target.rowCount)return res.status(404).json({error:"Profil introuvable."});const user=target.rows[0],own=String(user.id)===String(req.autodexUser.id);
    if(!own){const rel=await pool.query("SELECT 1 FROM autodex_friendships WHERE status='accepted' AND ((user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1))",[req.autodexUser.id,user.id]);if(!rel.rowCount)return res.status(403).json({error:"Tu dois être ami avec ce compte pour voir sa collection."});}
    const r=await pool.query("SELECT cars_json FROM autodex_cars WHERE user_id=$1",[user.id]);const cars=r.rows[0]?.cars_json||[];const brands={};let total=0,priced=0;
    for(const c of cars){const b=String(c.make||"Autre");brands[b]=(brands[b]||0)+1;if(c.price!==""&&c.price!==null&&Number.isFinite(Number(c.price))){total+=Number(c.price);priced++;}}
    res.json({username:user.username,profilePhoto:user.profile_photo||null,displaySkin:user.display_skin||"bronze",own,cars,stats:{carCount:cars.length,brandCount:Object.keys(brands).length,totalValue:priced?total:null,pricedCount:priced,brands:Object.entries(brands).sort((a,b)=>b[1]-a[1]).map(([name,count])=>({name,count}))}});
  }catch(e){console.error(e);res.status(500).json({error:"Impossible de charger ce profil."});}
});

const PRICE_DATA_URLS = {
  byYear: "https://karoto.fr/donnees/prix-modeles-annees.csv",
  byModel: "https://karoto.fr/donnees/cotes-modeles.csv"
};
const priceCache = { byYear: null, byModel: null };
const PRICE_CACHE_MS = 6 * 60 * 60 * 1000;

function parseCsvLine(line) {
  const fields = []; let field = "", quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') { field += '"'; i++; }
      else quoted = !quoted;
    } else if (ch === "," && !quoted) { fields.push(field); field = ""; }
    else field += ch;
  }
  fields.push(field); return fields;
}
function normalizeCarName(value) {
  return String(value || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]/g, "");
}
async function loadPriceCsv(key) {
  const cached = priceCache[key];
  if (cached && Date.now() - cached.loadedAt < PRICE_CACHE_MS) return cached.rows;
  const response = await fetch(PRICE_DATA_URLS[key], { headers: { "User-Agent": "AutoDex/1.0 price-estimator" } });
  if (!response.ok) throw new Error(`Source de prix indisponible (${response.status})`);
  const csv = (await response.text()).replace(/^\uFEFF/, "");
  const lines = csv.split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) throw new Error("Fichier de prix vide");
  const headers = parseCsvLine(lines[0]).map(h => h.trim());
  const rows = lines.slice(1).map(line => {
    const values = parseCsvLine(line);
    return Object.fromEntries(headers.map((header, i) => [header, (values[i] || "").trim()]));
  });
  priceCache[key] = { loadedAt: Date.now(), rows };
  return rows;
}
function validPrice(value) {
  const n = Number(String(value || "").replace(/\s/g, "").replace(",", "."));
  return Number.isFinite(n) && n > 0 ? Math.round(n) : null;
}

// Estimation de secours : utilisée uniquement quand les données d'annonces
// ne contiennent pas le modèle demandé ou que la source est indisponible.
function fallbackEstimate(make, model, year) {
  const m=normalizeCarName(model), b=normalizeCarName(make), y=Number(year);
  // Références indicatives actuelles en euros pour les modèles rares et versions limitées.
  const rare = [
    ["Bugatti","Tourbillon",3800000],["Bugatti","Bolide",4500000],["Bugatti","La Voiture Noire",16000000],["Bugatti","Centodieci",9000000],["Bugatti","Divo",6000000],["Bugatti","Mistral",6000000],["Bugatti","Chiron Super Sport",4200000],["Bugatti","Chiron Pur Sport",3800000],["Bugatti","Chiron Sport",3300000],["Bugatti","Chiron",3000000],["Bugatti","Veyron Super Sport",2300000],["Bugatti","Veyron",1600000],["Bugatti","EB110",2200000],
    ["Aston Martin","DBS Superleggera",300000],["Aston Martin","DBX707",260000],["Aston Martin","DB12",280000],["Aston Martin","DB11 AMR",210000],["Aston Martin","Vantage F1 Edition",180000],["Aston Martin","Valkyrie AMR Pro",5000000],["Aston Martin","Valkyrie Spider",4000000],["Aston Martin","Valkyrie",3200000],["Aston Martin","Valhalla",1000000],["Aston Martin","One-77",1800000],["Aston Martin","Vulcan",2500000],["Aston Martin","Victor",3000000],["Aston Martin","Valiant",3000000],["Aston Martin","Valour",1500000],["Aston Martin","V12 Speedster",1000000],
    ["Ferrari","F8 Tributo",430000],["Ferrari","F8 Spider",470000],["Ferrari","Roma Spider",320000],["Ferrari","Roma",260000],["Ferrari","296 GTB",330000],["Ferrari","296 GTS",370000],["Ferrari","812 Superfast",390000],["Ferrari","812 GTS",450000],["Ferrari","599 GTO",900000],["Ferrari","430 Scuderia",350000],["Ferrari","360 Challenge Stradale",450000],["Ferrari","F80",3800000],["Ferrari","LaFerrari Aperta",5000000],["Ferrari","LaFerrari",3500000],["Ferrari","Enzo Ferrari",3500000],["Ferrari","F50",3500000],["Ferrari","F40",2500000],["Ferrari","Daytona SP3",2500000],["Ferrari","Monza SP2",2000000],["Ferrari","Monza SP1",2000000],["Ferrari","812 Competizione A",1800000],["Ferrari","812 Competizione",1500000],["Ferrari","296 Speciale A",600000],["Ferrari","296 Speciale",550000],["Ferrari","SF90 XX Stradale",900000],["Ferrari","SF90 XX Spider",1000000],["Ferrari","SF90 Stradale",550000],["Ferrari","488 Pista",550000],["Ferrari","458 Speciale",450000],["Ferrari","Purosangue",500000],["Ferrari","12Cilindri",450000],["Ferrari","849 Testarossa",600000],
    ["Lamborghini","Veneno",8000000],["Lamborghini","Huracán Performante",330000],["Lamborghini","Huracán Tecnica",300000],["Lamborghini","Huracán EVO",270000],["Lamborghini","Gallardo Superleggera",220000],["Lamborghini","Aventador SV",550000],["Lamborghini","Aventador S",430000],["Lamborghini","Urus Performante",300000],["Lamborghini","Centenario",2500000],["Lamborghini","Sián Roadster",4000000],["Lamborghini","Sián FKP 37",3500000],["Lamborghini","Sesto Elemento",3000000],["Lamborghini","Essenza SCV12",2500000],["Lamborghini","Revuelto",650000],["Lamborghini","Huracán STO",350000],["Lamborghini","Aventador SVJ",650000],["Lamborghini","Countach LPI 800-4",2500000],["Lamborghini","Fenomeno",3000000],
    ["Koenigsegg","Jesko Absolut",4000000],["Koenigsegg","Jesko Attack",3500000],["Koenigsegg","Jesko",3300000],["Koenigsegg","Sadair's Spear",5000000],["Koenigsegg","CC850",4000000],["Koenigsegg","Agera RS",3500000],["Koenigsegg","Agera",2500000],["Koenigsegg","One:1",5000000],["Koenigsegg","Regera",2500000],["Koenigsegg","Gemera",2000000],
    ["McLaren","Artura",250000],["McLaren","675LT",350000],["McLaren","620R",300000],["McLaren","600LT",250000],["McLaren","650S",180000],["McLaren","570S",160000],["McLaren","F1 LM",20000000],["McLaren","F1 GTR",12000000],["McLaren","F1",20000000],["McLaren","W1",2200000],["McLaren","P1 GTR",3500000],["McLaren","P1",1500000],["McLaren","Senna GTR",1800000],["McLaren","Senna",1100000],["McLaren","Speedtail",2500000],["McLaren","Solus GT",3500000],["McLaren","Elva",2000000],["McLaren","765LT",500000],["McLaren","750S",350000],
    ["Pagani","Zonda HP Barchetta",17000000],["Pagani","Zonda Revolucion",8000000],["Pagani","Zonda Cinque",10000000],["Pagani","Zonda R",6000000],["Pagani","Zonda",3000000],["Pagani","Huayra R",4000000],["Pagani","Huayra BC",3500000],["Pagani","Huayra Codalunga",7000000],["Pagani","Huayra",2500000],["Pagani","Utopia Roadster",4000000],["Pagani","Utopia",3500000],["Pagani","Imola",5000000],
    ["Rimac","Nevera R",2500000],["Rimac","Nevera",2200000],["Porsche","918 Spyder",1300000],["Porsche","Carrera GT",1100000],["Porsche","911 GT1",10000000],["Porsche","911 GT2 RS",350000],["Porsche","911 GT3 RS",300000],["Porsche","911 S/T",400000],["Porsche","911 Sport Classic",400000],
    ["Mercedes-AMG","CLK GTR",4000000],["Mercedes-AMG","AMG ONE",3000000],["Gordon Murray Automotive","T.50s Niki Lauda",4000000],["Gordon Murray Automotive","T.50",2500000],["Gordon Murray Automotive","T.33 Spider",2000000],["Gordon Murray Automotive","T.33",1800000],
    ["Hennessey","Venom F5 Revolution",3000000],["Hennessey","Venom F5",2500000],["Hennessey","Venom GT",1200000],["SSC North America","Tuatara Aggressor",3000000],["SSC North America","Tuatara",2000000],["W Motors","Lykan HyperSport",3500000],["W Motors","Fenyr SuperSport",1800000],
    ["Automobili Pininfarina","B95 Gotham",5000000],["Automobili Pininfarina","B95",4500000],["Automobili Pininfarina","Battista",2200000],["Apollo Automobil","Intensa Emozione",3000000],["Lotus","Evija",2200000],["Zenvo","Aurora Agil",3000000],["Zenvo","Aurora Tur",3000000],["Zenvo","TSR-GT",2000000],["Zenvo","TSR-S",1800000],
    ["Ford","GT40",5000000],["Ford","GT Mk II",1800000],["Ford","GT",600000],["Toyota","2000GT",1000000],["Jaguar","XJ220",700000],["Jaguar","XJR-15",1500000],["Dodge","Viper ACR",250000],["Lexus","LFA",800000]
  ];
  let base=null;
  for(const [brand,modelName,price] of rare){if(normalizeCarName(brand)===b&&normalizeCarName(modelName)===m){base=price;break;}}
  if(base===null){
    const special=[[/lavoiturenoire/,16000000],[/valkyrieamrpro/,5000000],[/valkyriespider/,4000000],[/valkyrie/,3200000],[/laferrariaperta/,5000000],[/laferrari/,3500000],[/daytonasp3/,2500000],[/monzasp[12]/,2000000],[/sf90xx/,900000],[/sf90/,550000],[/bolide/,4500000],[/tourbillon/,3800000],[/centodieci/,9000000],[/divo/,6000000],[/chiron/,3000000],[/veyron/,1600000],[/jeskoabsolut/,4000000],[/jeskoattack/,3500000],[/jesko/,3300000],[/cc850/,4000000],[/agera/,2500000],[/regera/,2500000],[/zondahpbarchetta/,17000000],[/zondacinque/,10000000],[/zonda/,3000000],[/huayracodalunga/,7000000],[/huayra/,2500000],[/utopia/,3500000],[/sennagtr/,1800000],[/senna/,1100000],[/speedtail/,2500000],[/solusgt/,3500000],[/neverar/,2500000],[/nevera/,2200000],[/amgone/,3000000],[/valhalla/,1000000],[/one77/,1800000],[/vulcan/,2500000],[/victor/,3000000],[/revuelto/,650000],[/sian/,3500000],[/veneno/,8000000],[/sestoelemento/,3000000],[/essenzascv12/,2500000],[/918spyder/,1300000],[/carreragt/,1100000],[/911gt1/,10000000],[/t50snikilauda/,4000000],[/^t50$/,2500000],[/^t33$/,1800000],[/battista/,2200000],[/b95/,4500000],[/evija/,2200000],[/xj220/,700000],[/lfa/,800000],[/gt40/,5000000]];
    for(const [pattern,price] of special){if(pattern.test(m)){base=price;break;}}
  }
  if(base===null){const known=[[/f80/,3500000],[/laferrari/,3500000],[/daytonasp3/,2200000],[/monzasp2/,1800000],[/sf90/,500000],[/296/,330000],[/812/,400000],[/purosangue/,450000],[/488pista/,450000],[/458speciale/,350000],[/revuelto/,600000],[/aventador/,450000],[/huracansto/,350000],[/huracan/,250000],[/temerario/,350000],[/urus/,250000],[/p1/,1500000],[/765lt/,500000],[/720s/,300000],[/750s/,350000],[/911gt2rs/,350000],[/911gt3rs/,300000],[/911turbos/,250000],[/911gt3/,220000],[/911/,150000]];for(const [pattern,price] of known){if(pattern.test(m)){base=price;break;}}}
  if(base===null){const highEnd=/ferrari|lamborghini|bugatti|koenigsegg|pagani|rimac|mclaren|astonmartin|maserati|bentley|rollsroyce|lotus|porsche|maybach|gordonmurray|hennessey|zenvo|apollo|automobilipininfarina|ssc|wmotors/.test(b);const luxury=/mercedes|bmw|audi|rangerover|landrover|lexus|genesis|lucid|polestar|alpine/.test(b);const family=/suv|crossover|x[1-7]|q[2-8]|gle|gls|glc|cayenne|urus|defender|rangerover/.test(m);const sporty=/gt|sport|coupe|rs|amg|m[0-9]|typer|supra|z4|mustang|corvette|camaro|wrx|sti/.test(m);base=highEnd?(sporty?180000:120000):luxury?(family?75000:sporty?65000:50000):(family?35000:sporty?45000:25000);}
  // L'année module la valeur, mais la décote des voitures de collection reste volontairement modérée.
  let price=base;if(Number.isInteger(y)&&y>=1886&&y<=2026){const age=Math.max(0,2026-y);const factor=base>=1000000?Math.max(0.68,1-age*0.006):base>=250000?Math.max(0.42,1-age*0.035):base>=80000?Math.max(0.2,1-age*0.055):Math.max(0.08,1-age*0.07);price*=factor;}
  return Math.max(500,Math.round(price/500)*500);
}
function estimatePriceRange(price) {
  // Fourchette indicative autour du prix de référence : plus large pour les modèles rares/luxueux.
  const p = Number(price) || 0;
  const lowFactor = p >= 1000000 ? 0.65 : p >= 250000 ? 0.72 : p >= 80000 ? 0.78 : 0.82;
  const highFactor = p >= 1000000 ? 1.65 : p >= 250000 ? 1.45 : p >= 80000 ? 1.35 : 1.28;
  const round = n => Math.max(500, Math.round(n / 500) * 500);
  return { priceMin: round(p * lowFactor), priceMax: round(p * highFactor) };
}
function sendFallback(res, make, model, year, reason = "") {
  const price = fallbackEstimate(make, model, year);
  return res.json({
    price, ...estimatePriceRange(price), make, model, year: Number(year) || null, basis: "fallback",
    source: reason.includes("hypercar") ? "Référence indicative dédiée à cette hypercar/version rare ; le marché réel peut varier fortement" : "Estimation automatique approximative basée sur la marque, le modèle et l'année" + (reason ? ` (${reason})` : ""),
    sourceUrl: reason.includes("hypercar") ? null : "https://karoto.fr/donnees", license: "Estimation indicative"
  });
}
function isRareHypercarReference(make, model) {
  const b=normalizeCarName(make), m=normalizeCarName(model);
  const brands={bugatti:["tourbillon","bolide","lavoiturenoire","centodieci","divo","mistral","chironsupersport","chironpursport","chiron","veyron","veyronsupersport","eb110"],astonmartin:["dbssuperleggera","dbx707","db12","db11amr","vantagef1edition","valkyrieamrpro","valkyri es","valkyriespider","valkyrie","valhalla","one77","vulcan","victor","valiant","valour"],ferrari:["f8tributo","f8spider","romaspider","roma","296gtb","296gts","812superfast","812gts","599gto","430scuderia","360challengestradale","f80","laferrariaperta","laferrari","enzoferrari","f50","f40","daytonasp3","monzasp2","monzasp1","812competizionea","812competizione","296specialea","296speciale","sf90xxstradale","sf90xxspider","sf90stradale","488pista","458speciale"],lamborghini:["huracanperformante","huracantecnica","huracanevo","gallardosuperleggera","aventadorsv","aventadors","urusperformante","veneno","centenario","sianroadster","sianfkp37","sestoelemento","essenzascv12","revuelto","huracansto","aventadorsvj","countachlpi8004"],koenigsegg:["jeskoabsolut","jeskoattack","jesko","sadairsspear","cc850","agerars","agera","one1","regera"],mclaren:["artura","675lt","620r","600lt","650s","570s","f1lm","f1gtr","f1","w1","p1gtr","p1","sennagtr","senna","speedtail","solusgt","elva","765lt"],pagani:["zondahpbarchetta","zondarevolucion","zondacinque","zondar","zonda","huayrar","huayrabc","huayracodalunga","huayra","utopiaroadster","utopia","imola"],rimac:["neverar","nevera"],porsche:["918spyder","carreragt","911gt1"],mercedesamg:["clkgtr","amgone"],mercedesbenz:["clkgtr","amgone"],gordonmurrayautomotive:["t50snikilauda","t50","t33spider","t33"],hennessey:["venomf5revolution","venomf5","venomgt"],sscnorthamerica:["tuataraaggressor","tuatara"],wmotors:["lykanhypersport","fenyrsupersport"],automobilipininfarina:["b95gotham","b95","battista"],apolloautomobil:["intensaemozione","ie"],lotus:["evija"],zenvo:["auroraagil","auroratur","tsrgt","tsrs"]};
  return Boolean((brands[b]||[]).includes(m));
}
app.get("/api/price-estimate", async (req, res) => {
  const make = String(req.query.make || "").trim();
  const model = String(req.query.model || "").trim();
  const year = Number(req.query.year);
  if (!make || !model) return res.status(400).json({ error: "Indique une marque et un modèle." });
  // Référence spécialisée pour la CC8S : le CSV généraliste peut sous-évaluer les modèles
  // ultra-rares. Les estimations publiques sont très dispersées et aucune vente publique
  // récente ne permet d'établir une cote certaine ; on affiche donc une large fourchette.
  if (normalizeCarName(make) === "koenigsegg" && normalizeCarName(model) === "cc8s") {
    return res.json({
      price: 1500000, priceMin: 1100000, priceMax: 2200000,
      make: "Koenigsegg", model: "CC8S", year: Number.isInteger(year) && year >= 1886 && year <= 2100 ? year : null,
      basis: "rare-model-editorial-range", confidence: "faible — très peu de transactions publiques",
      source: "Fourchette indicative de modèle ultra-rare : références spécialisées divergentes ; aucune vente publique récente suffisamment comparable. À confirmer selon châssis, provenance, état et historique d'entretien.",
      sourceUrl: "https://auto-index.co/car/koenigsegg-cc8s-2002",
      additionalSources: ["https://hiconium.com/vehicles/koenigsegg/cc8s", "https://www.octanefiles.com/cars/koenigsegg-cc8s"],
      license: "Références publiques consultées ; estimation indicative, non une expertise"
    });
  }
  if (model === "Autre modèle" || make === "Autre / non listée") return sendFallback(res, make, model, year, "modèle personnalisé");
  if (isRareHypercarReference(make, model)) return sendFallback(res, make, model, year, "référence dédiée à cette hypercar/version rare");
  try {
    const [yearRows, modelRows] = await Promise.all([loadPriceCsv("byYear"), loadPriceCsv("byModel")]);
    const wantedMake = normalizeCarName(make), wantedModel = normalizeCarName(model);
    const matchesYear = yearRows.filter(row => normalizeCarName(row.marque) === wantedMake && normalizeCarName(row.modele) === wantedModel);
    const exactYear = Number.isInteger(year) && year >= 1886 && year <= 2100
      ? matchesYear.find(row => Number(row.annee) === year && validPrice(row.prix_median_france_eur)) : null;
    if (exactYear) return res.json({
      price: validPrice(exactYear.prix_median_france_eur), ...estimatePriceRange(validPrice(exactYear.prix_median_france_eur)), make: exactYear.marque, model: exactYear.modele,
      year: Number(exactYear.annee), mileageMedian: Number(exactYear.km_median_france) || null,
      listings: Number(exactYear.annonces_france) || null, basis: "year", date: exactYear.date_extraction || "",
      source: "Karoto — médiane des annonces françaises pour ce modèle et cette année",
      sourceUrl: "https://karoto.fr/donnees", license: "Licence Ouverte 2.0"
    });
    const modelRow = modelRows.find(row => normalizeCarName(row.marque) === wantedMake && normalizeCarName(row.modele) === wantedModel && validPrice(row.prix_median_france_eur));
    if (modelRow) return res.json({
      price: validPrice(modelRow.prix_median_france_eur), ...estimatePriceRange(validPrice(modelRow.prix_median_france_eur)), make: modelRow.marque, model: modelRow.modele,
      year: Number(modelRow.reference_annee) || null, mileageMedian: Number(modelRow.reference_km) || null,
      listings: Number(modelRow.annonces_france) || null, basis: "model", date: modelRow.date_calcul || "",
      requestedYear: Number.isInteger(year) && year >= 1886 && year <= 2100 ? year : null,
      source: "Karoto — médiane des annonces françaises du modèle, toutes années confondues",
      sourceUrl: "https://karoto.fr/donnees", license: "Licence Ouverte 2.0"
    });
    return sendFallback(res, make, model, year, "pas assez d'annonces comparables");
  } catch (error) {
    console.error("Price lookup error:", error?.message || error);
    return sendFallback(res, make, model, year, "source de prix indisponible");
  }
});
// Retourne une erreur JSON claire lorsque le corps d’une requête dépasse la limite Express.
app.use((err, _req, res, next) => {
  if (err?.type === "entity.too.large" || err?.status === 413) {
    return res.status(413).json({ error: "Requête trop volumineuse (limite serveur de 200 Mo). Compresse la photo ou envoie moins de photos à la fois." });
  }
  if (err) {
    console.error("Request parsing error:", err.message || err);
    return res.status(err.status || 400).json({ error: "Requête invalide. Vérifie les données envoyées et réessaie." });
  }
  next();
});
app.get("/api/status", (_req, res) => res.json({ ready: true, message: "AutoDex FINAL prêt", priceEstimatesAvailable: true, aiAvailable: false }));
if (pool) initDatabase().then(() => app.listen(port, () => console.log(`AutoDex FINAL running on port ${port}`))).catch(e => { console.error("Database initialization failed:",e); process.exit(1); });
else app.listen(port, () => console.log(`AutoDex FINAL running on port ${port}; DATABASE_URL missing`));
