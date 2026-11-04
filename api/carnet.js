// ============================================================
// CARNET — api/carnet.js — lot 1 (04/11/2026)
// Annuaire commun des associés et collaborateurs de FIDAL Notaires.
// Fonction serveur UNIQUE à actions (limite Vercel Hobby : 12 fonctions).
//
// Appel de l'écran d'administration : POST /api/carnet { action, ... }
//   En-tête Authorization: Bearer <jeton> (sauf actions "etat" et "connexion")
// Appel des autres outils (lecture seule, de serveur à serveur) :
//   GET /api/carnet?action=lecture[&inactifs=1]   en-tête  X-Carnet-Cle: <clé de l'outil>
//
// Variables d'environnement Vercel :
//   DATABASE_URL            chaîne Neon (rôle matrice_owner, projet neon-fuchsia-pillow)
//   CARNET_MDP              mot de passe de l'administrateur (JFD seul)
//   CARNET_CLE_CHIFFREMENT  clé AES-256 en base64 (32 octets) — copie de secours sur clé physique
//   CARNET_SECRET           (facultatif) secret de signature des sessions ; à défaut, dérivé du mot de passe
// ============================================================

const { neon } = require("@neondatabase/serverless");
const crypto = require("crypto");

const DUREE_SESSION_MS = 8 * 60 * 60 * 1000;
const CHAMPS_CHIFFRES = ["fonction", "service", "telephone", "portable", "courriel"];
const LIBELLES = { nom: "nom", prenom: "prénom", civilite: "civilité", categorie: "catégorie", initiales: "initiales", site_id: "site",
  fonction: "fonction", service: "service", telephone: "téléphone", portable: "portable", courriel: "courriel" };

// ---------- utilitaires ----------
const sha256 = (t) => crypto.createHash("sha256").update(String(t), "utf8").digest();
function egalSur(a, b) { return crypto.timingSafeEqual(sha256(a), sha256(b)); }
function secretSession() { return sha256("carnet:" + (process.env.CARNET_SECRET || process.env.CARNET_MDP || "")); }
function signer(exp) { return crypto.createHmac("sha256", secretSession()).update(String(exp)).digest("base64url"); }
function creerJeton() { const exp = Date.now() + DUREE_SESSION_MS; return `${exp}.${signer(exp)}`; }
function jetonValide(j) {
  if (!j || typeof j !== "string") return false;
  const [e, s] = j.split(".");
  const exp = Number(e);
  if (!s || !Number.isFinite(exp) || exp < Date.now()) return false;
  const att = signer(exp);
  return att.length === s.length && crypto.timingSafeEqual(Buffer.from(att), Buffer.from(s));
}
function texte(v, max = 200) { return String(v == null ? "" : v).replace(/\s+/g, " ").trim().slice(0, max); }
function lireCorps(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string" && req.body) { try { return JSON.parse(req.body); } catch { return {}; } }
  return {};
}

// ---------- chiffrement des coordonnées (AES-256-GCM) ----------
function cleChiffrement() {
  const b = Buffer.from(String(process.env.CARNET_CLE_CHIFFREMENT || ""), "base64");
  if (b.length !== 32) throw new Error("Clé de chiffrement absente ou invalide (CARNET_CLE_CHIFFREMENT : 32 octets en base64).");
  return b;
}
function chiffrer(valeur) {
  const v = texte(valeur, 300);
  if (!v) return null;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", cleChiffrement(), iv);
  const ct = Buffer.concat([c.update(v, "utf8"), c.final()]);
  return "v1:" + Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
}
function dechiffrer(enc) {
  if (!enc) return "";
  if (!String(enc).startsWith("v1:")) return "";
  const b = Buffer.from(String(enc).slice(3), "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", cleChiffrement(), b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
}
// empreinte du courriel (doublons) : HMAC avec la clé de chiffrement, le courriel n'est jamais stocké en clair
function empreinteCourriel(c) {
  const v = texte(c, 300).toLowerCase();
  if (!v || !v.includes("@")) return null;
  return crypto.createHmac("sha256", cleChiffrement()).update("courriel:" + v).digest("base64url");
}

// ---------- lecture des personnes ----------
async function personnes(sql, avecInactifs) {
  const lignes = avecInactifs
    ? await sql`SELECT p.*, s.nom AS site_nom, s.code_postal AS site_cp, s.adresse AS site_adresse, s.telephone AS site_tel
                FROM carnet_personne p LEFT JOIN carnet_site s ON s.id = p.site_id ORDER BY p.nom, p.prenom`
    : await sql`SELECT p.*, s.nom AS site_nom, s.code_postal AS site_cp, s.adresse AS site_adresse, s.telephone AS site_tel
                FROM carnet_personne p LEFT JOIN carnet_site s ON s.id = p.site_id WHERE p.actif ORDER BY p.nom, p.prenom`;
  return lignes.map((p) => ({
    id: p.id, nom: p.nom, prenom: p.prenom, civilite: p.civilite || "", categorie: p.categorie, initiales: p.initiales || "",
    actif: p.actif, inactif_le: p.inactif_le, maj_le: p.maj_le,
    fonction: dechiffrer(p.fonction_c), service: dechiffrer(p.service_c), telephone: dechiffrer(p.telephone_c), portable: dechiffrer(p.portable_c), courriel: dechiffrer(p.courriel_c),
    site_id: p.site_id, site: p.site_id ? { nom: p.site_nom, code_postal: p.site_cp || "", adresse: p.site_adresse || "", telephone: p.site_tel || "" } : null,
  }));
}
async function journaliser(sql, personneId, personne, action, champs, origine = "ecran") {
  await sql`INSERT INTO carnet_journal (personne_id, personne, action, champs, origine)
            VALUES (${personneId}, ${personne}, ${action}, ${champs || null}, ${origine})`;
}
const nomComplet = (p) => [p.prenom, p.nom].filter(Boolean).join(" ");

function valider(c) {
  const p = {
    nom: texte(c.nom, 120),
    prenom: texte(c.prenom, 120),
    civilite: ["Monsieur", "Madame"].includes(c.civilite) ? c.civilite : null,
    categorie: c.categorie === "associe" ? "associe" : "collaborateur",
    initiales: texte(c.initiales, 10).toUpperCase() || null,
    site_id: Number.isFinite(parseInt(c.site_id, 10)) ? parseInt(c.site_id, 10) : null,
    fonction: texte(c.fonction, 120), service: texte(c.service, 160), telephone: texte(c.telephone, 40), portable: texte(c.portable, 40), courriel: texte(c.courriel, 200).toLowerCase(),
  };
  if (!p.nom) throw new Error("Le nom est obligatoire.");
  if (p.courriel && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(p.courriel)) throw new Error("Courriel invalide : " + p.courriel);
  return p;
}

// ---------- actions de l'administrateur ----------
const actions = {
  async liste(sql) {
    const [liste, sites] = await Promise.all([personnes(sql, true), sql`SELECT * FROM carnet_site ORDER BY nom`]);
    return { personnes: liste, sites };
  },

  async enregistrer(sql, c) {
    const p = valider(c);
    const emp = empreinteCourriel(p.courriel);
    const id = parseInt(c.id, 10);
    if (emp) {
      const autre = Number.isFinite(id)
        ? await sql`SELECT id, prenom, nom FROM carnet_personne WHERE courriel_empreinte = ${emp} AND id <> ${id}`
        : await sql`SELECT id, prenom, nom FROM carnet_personne WHERE courriel_empreinte = ${emp}`;
      if (autre.length) throw new Error(`Ce courriel est déjà celui de ${nomComplet(autre[0])}.`);
    }
    if (!Number.isFinite(id)) {
      const r = await sql`INSERT INTO carnet_personne (nom, prenom, civilite, categorie, initiales, site_id, fonction_c, service_c, telephone_c, portable_c, courriel_c, courriel_empreinte)
        VALUES (${p.nom}, ${p.prenom}, ${p.civilite}, ${p.categorie}, ${p.initiales}, ${p.site_id},
                ${chiffrer(p.fonction)}, ${chiffrer(p.service)}, ${chiffrer(p.telephone)}, ${chiffrer(p.portable)}, ${chiffrer(p.courriel)}, ${emp}) RETURNING id`;
      await journaliser(sql, r[0].id, nomComplet(p), "création", null);
      return { ok: true, id: r[0].id };
    }
    const avant = (await personnes(sql, true)).find((x) => x.id === id);
    if (!avant) throw new Error("Personne introuvable.");
    const modifies = Object.keys(LIBELLES).filter((k) => String(avant[k] == null ? "" : avant[k]) !== String(p[k] == null ? "" : p[k]));
    if (!modifies.length) return { ok: true, id, inchange: true };
    await sql`UPDATE carnet_personne SET nom = ${p.nom}, prenom = ${p.prenom}, civilite = ${p.civilite}, categorie = ${p.categorie},
              initiales = ${p.initiales}, site_id = ${p.site_id}, fonction_c = ${chiffrer(p.fonction)}, service_c = ${chiffrer(p.service)},
              telephone_c = ${chiffrer(p.telephone)}, portable_c = ${chiffrer(p.portable)}, courriel_c = ${chiffrer(p.courriel)}, courriel_empreinte = ${emp}, maj_le = NOW()
              WHERE id = ${id}`;
    await journaliser(sql, id, nomComplet(p), "correction", modifies.map((k) => LIBELLES[k]).join(", "));
    return { ok: true, id };
  },

  async statut(sql, c) {
    const id = parseInt(c.id, 10), actif = !!c.actif;
    const r = await sql`UPDATE carnet_personne SET actif = ${actif}, inactif_le = ${actif ? null : new Date().toISOString()}, maj_le = NOW()
                        WHERE id = ${id} RETURNING prenom, nom`;
    if (!r.length) throw new Error("Personne introuvable.");
    await journaliser(sql, id, nomComplet(r[0]), actif ? "réactivation" : "passage inactif", null);
    return { ok: true };
  },

  async site_enregistrer(sql, c) {
    const nom = texte(c.nom, 80).toUpperCase(), id = parseInt(c.id, 10);
    if (!nom) throw new Error("Le nom du site est obligatoire.");
    const v = [texte(c.code_postal, 10), texte(c.adresse, 200), texte(c.telephone, 40)];
    if (Number.isFinite(id)) await sql`UPDATE carnet_site SET nom = ${nom}, code_postal = ${v[0]}, adresse = ${v[1]}, telephone = ${v[2]} WHERE id = ${id}`;
    else await sql`INSERT INTO carnet_site (nom, code_postal, adresse, telephone) VALUES (${nom}, ${v[0]}, ${v[1]}, ${v[2]})`;
    await journaliser(sql, null, "Site " + nom, Number.isFinite(id) ? "correction du site" : "création du site", null);
    return { ok: true };
  },

  async site_supprimer(sql, c) {
    const id = parseInt(c.id, 10);
    const n = await sql`SELECT COUNT(*)::int AS n FROM carnet_personne WHERE site_id = ${id}`;
    if (n[0].n) throw new Error(`Ce site est encore celui de ${n[0].n} personne${n[0].n > 1 ? "s" : ""} : changez-les de site d'abord.`);
    const r = await sql`DELETE FROM carnet_site WHERE id = ${id} RETURNING nom`;
    if (r.length) await journaliser(sql, null, "Site " + r[0].nom, "suppression du site", null);
    return { ok: true };
  },

  // import initial depuis les deux fichiers du Drive (lus dans le navigateur) ; les doublons de courriel sont écartés
  async importer(sql, c) {
    const lignes = Array.isArray(c.personnes) ? c.personnes.slice(0, 500) : [];
    const sitesIn = Array.isArray(c.sites) ? c.sites.slice(0, 50) : [];
    for (const s of sitesIn) {
      const nom = texte(s.nom, 80).toUpperCase();
      if (!nom) continue;
      await sql`INSERT INTO carnet_site (nom, code_postal, adresse, telephone) VALUES (${nom}, ${texte(s.code_postal, 10)}, ${texte(s.adresse, 200)}, ${texte(s.telephone, 40)})
                ON CONFLICT (nom) DO UPDATE SET
                  code_postal = COALESCE(NULLIF(carnet_site.code_postal, ''), EXCLUDED.code_postal),
                  adresse = COALESCE(NULLIF(carnet_site.adresse, ''), EXCLUDED.adresse),
                  telephone = COALESCE(NULLIF(carnet_site.telephone, ''), EXCLUDED.telephone)`;
    }
    const sites = await sql`SELECT id, nom FROM carnet_site`;
    const idSite = (n) => { const x = sites.find((s) => s.nom === texte(n, 80).toUpperCase()); return x ? x.id : null; };
    let crees = 0; const ecartes = [];
    for (const l of lignes) {
      let p;
      try { p = valider({ ...l, site_id: idSite(l.site) }); } catch (e) { ecartes.push(`${texte(l.prenom)} ${texte(l.nom)} : ${e.message}`); continue; }
      const emp = empreinteCourriel(p.courriel);
      if (emp && (await sql`SELECT 1 FROM carnet_personne WHERE courriel_empreinte = ${emp}`).length) { ecartes.push(`${nomComplet(p)} : déjà présent`); continue; }
      const r = await sql`INSERT INTO carnet_personne (nom, prenom, civilite, categorie, initiales, site_id, fonction_c, service_c, telephone_c, portable_c, courriel_c, courriel_empreinte)
        VALUES (${p.nom}, ${p.prenom}, ${p.civilite}, ${p.categorie}, ${p.initiales}, ${p.site_id},
                ${chiffrer(p.fonction)}, ${chiffrer(p.service)}, ${chiffrer(p.telephone)}, ${chiffrer(p.portable)}, ${chiffrer(p.courriel)}, ${emp}) RETURNING id`;
      await journaliser(sql, r[0].id, nomComplet(p), "création", null, "import");
      crees++;
    }
    return { ok: true, crees, ecartes };
  },

  async journal(sql) {
    return { lignes: await sql`SELECT le, personne, action, champs, origine FROM carnet_journal ORDER BY le DESC, id DESC LIMIT 500` };
  },

  async cles(sql) {
    return { cles: await sql`SELECT id, outil, debut, cree_le, revoquee_le, dernier_usage FROM carnet_cle ORDER BY revoquee_le NULLS FIRST, outil` };
  },
  async cle_creer(sql, c) {
    const outil = texte(c.outil, 60);
    if (!outil) throw new Error("Indiquez le nom de l'outil.");
    const cle = "carnet_" + crypto.randomBytes(32).toString("base64url");
    await sql`INSERT INTO carnet_cle (outil, empreinte, debut) VALUES (${outil}, ${sha256(cle).toString("base64url")}, ${cle.slice(0, 12)})`;
    await journaliser(sql, null, "Clé " + outil, "création de clé d'accès", null);
    return { ok: true, cle };   // affichée UNE seule fois
  },
  async cle_revoquer(sql, c) {
    const r = await sql`UPDATE carnet_cle SET revoquee_le = NOW() WHERE id = ${parseInt(c.id, 10)} AND revoquee_le IS NULL RETURNING outil`;
    if (r.length) await journaliser(sql, null, "Clé " + r[0].outil, "révocation de clé d'accès", null);
    return { ok: true };
  },
};

// ---------- point d'entrée ----------
module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  const fin = (code, obj) => { res.statusCode = code; res.end(JSON.stringify(obj)); };

  const manque = ["DATABASE_URL", "CARNET_MDP", "CARNET_CLE_CHIFFREMENT"].filter((v) => !process.env[v]);
  let cleOk = true;
  try { if (!manque.includes("CARNET_CLE_CHIFFREMENT")) cleChiffrement(); } catch { cleOk = false; }

  // ----- lecture par un autre outil (serveur à serveur) -----
  const q = req.query || {};
  if (req.method === "GET" && q.action === "lecture") {
    if (manque.length || !cleOk) return fin(503, { erreur: "CARNET n'est pas configuré." });
    const cle = String(req.headers["x-carnet-cle"] || "");
    if (!cle) return fin(401, { erreur: "Clé d'accès absente." });
    try {
      const sql = neon(process.env.DATABASE_URL);
      const r = await sql`UPDATE carnet_cle SET dernier_usage = NOW() WHERE empreinte = ${sha256(cle).toString("base64url")} AND revoquee_le IS NULL RETURNING outil`;
      if (!r.length) { await new Promise((x) => setTimeout(x, 500)); return fin(401, { erreur: "Clé d'accès refusée." }); }
      return fin(200, { personnes: await personnes(sql, q.inactifs === "1") });
    } catch (e) { console.error("[carnet] lecture", e); return fin(500, { erreur: "Erreur serveur" }); }
  }

  if (req.method !== "POST") return fin(405, { erreur: "Méthode non autorisée" });
  const corps = lireCorps(req);
  const action = texte(corps.action, 40);

  if (action === "etat") return fin(200, { pret: !manque.length && cleOk, manque, cle_invalide: !cleOk });
  if (manque.length) return fin(500, { erreur: "Variables absentes sur Vercel : " + manque.join(", ") });
  if (!cleOk) return fin(500, { erreur: "CARNET_CLE_CHIFFREMENT invalide : il faut 32 octets en base64." });

  if (action === "connexion") {
    if (!egalSur(String(corps.mdp || ""), process.env.CARNET_MDP)) {
      await new Promise((x) => setTimeout(x, 800));
      return fin(401, { erreur: "Mot de passe incorrect." });
    }
    return fin(200, { jeton: creerJeton() });
  }

  const auth = String(req.headers["authorization"] || "");
  if (!jetonValide(auth.startsWith("Bearer ") ? auth.slice(7) : "")) return fin(401, { erreur: "Session expirée, reconnectez-vous." });
  const fn = actions[action];
  if (!fn) return fin(400, { erreur: "Action inconnue : " + action });
  try {
    return fin(200, await fn(neon(process.env.DATABASE_URL), corps, req));
  } catch (e) {
    console.error("[carnet]", action, e);
    return fin(e.message && !/relation|column|syntax/.test(e.message) ? 400 : 500, { erreur: e.message || "Erreur serveur" });
  }
};
