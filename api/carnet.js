// ============================================================
// CARNET — api/carnet.js — lot 1 (04/11/2026) ; signatures, export, contrôle des doublons (05/11/2026) ;
//   lot 3 (16/11/2026) : comptes des personnes et accès aux outils ; refondu le 19/11/2026 : PROFILS à interrupteurs
//   (Immobilier, Famille, Affaires, International, Premium, Admin général) + colonne « version payante »
//   26/11/2026 : colonne « actes et taxes » (accès au dossier des actes taxés), à part des profils, emportée par l'admin général
// Annuaire commun des associés et collaborateurs de FIDAL Notaires.
// Fonction serveur UNIQUE à actions (limite Vercel Hobby : 12 fonctions).
//
// Appel de l'écran d'administration : POST /api/carnet { action, ... }
//   En-tête Authorization: Bearer <jeton> (sauf actions "etat" et "connexion")
// Appel des autres outils (lecture seule, de serveur à serveur) :
//   GET /api/carnet?action=lecture[&inactifs=1]   en-tête  X-Carnet-Cle: <clé de l'outil>
// Appel des personnes (page d'accueil et outils, depuis le navigateur, origines autorisées seulement) :
//   POST /api/carnet { action: "p_connexion" | "p_changer" | "p_moi" | "p_oubli", ... }
//
// Variables d'environnement Vercel :
//   DATABASE_URL            chaîne Neon (rôle matrice_owner, projet neon-fuchsia-pillow)
//   CARNET_MDP              mot de passe de l'administrateur (JFD seul)
//   CARNET_CLE_CHIFFREMENT  clé AES-256 en base64 (32 octets) — copie de secours sur clé physique
//   CARNET_SECRET           (facultatif) secret de signature des sessions ; à défaut, dérivé du mot de passe
//   CARNET_ORIGINES         (facultatif) origines supplémentaires autorisées à connecter les personnes, séparées par des virgules
// ============================================================

const { neon } = require("@neondatabase/serverless");
const crypto = require("crypto");
const { ronde } = require("../lib/ronde");

const DUREE_SESSION_MS = 8 * 60 * 60 * 1000;
const CHAMPS_CHIFFRES = ["fonction", "service", "ligne2", "telephone", "portable", "courriel"];
// 05/11 : couleurs de la charte proposées pour le nom dans la signature (défaut = bleu-vert du modèle de JFD)
const COULEURS = ["#33838B", "#0F2238", "#657D96", "#E3CC7A", "#82AA98", "#FF982D", "#6DD5DC"];   // charte officielle sauf le jaune (05/11 soir)
const LIBELLES = { nom: "nom", prenom: "prénom", civilite: "civilité", categorie: "catégorie", initiales: "initiales", site_id: "site",
  fonction: "fonction", service: "service", telephone: "téléphone", portable: "portable", courriel: "courriel", sans_signature: "sans signature", ligne2: "deuxième ligne de signature", couleur: "couleur du nom" };

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

// ---------- comptes des personnes (lot 3, 16/11/2026) ----------
const DUREE_PERSONNE_MS = 10 * 60 * 60 * 1000;          // durée d'une connexion de personne (à confirmer par JFD)
const DUREE_PROVISOIRE_MS = 7 * 24 * 60 * 60 * 1000;    // validité d'un mot de passe provisoire
const MDP_LONGUEUR_MIN = 10;
const ESSAIS_MAX = 5, BLOCAGE_MS = 15 * 60 * 1000;
const ORIGINES_PERSONNES = ["https://phare-ashy.vercel.app"]
  .concat(String(process.env.CARNET_ORIGINES || "").split(",").map((x) => x.trim().replace(/\/+$/, "")).filter(Boolean));
// le jeton d'une personne n'a pas la forme de celui de l'administrateur et n'est pas signé sur la même donnée :
// il ne peut jamais ouvrir l'écran d'administration
function signerPersonne(id, exp) { return crypto.createHmac("sha256", secretSession()).update(`personne:${id}:${exp}`).digest("base64url"); }
function creerJetonPersonne(id) { const exp = Date.now() + DUREE_PERSONNE_MS; return { jeton: `p.${id}.${exp}.${signerPersonne(id, exp)}`, expire: exp }; }
function lireJetonPersonne(j) {
  const m = /^p\.(\d+)\.(\d+)\.([A-Za-z0-9_-]+)$/.exec(String(j || ""));
  if (!m) return null;
  const id = Number(m[1]), exp = Number(m[2]);
  if (!Number.isFinite(exp) || exp < Date.now()) return null;
  const att = signerPersonne(id, exp);
  if (att.length !== m[3].length || !crypto.timingSafeEqual(Buffer.from(att), Buffer.from(m[3]))) return null;
  return { id, emis: exp - DUREE_PERSONNE_MS };
}
function hacherMdp(mdp, sel) { return crypto.scryptSync(String(mdp), String(sel), 32).toString("base64url"); }
function mdpEgal(mdp, sel, empreinte) {
  const a = Buffer.from(hacherMdp(mdp, sel)), b = Buffer.from(String(empreinte));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
// mot de passe provisoire : trois groupes de quatre signes, sans caractères qui se confondent (0/o, 1/l/i)
function mdpProvisoire() {
  const signes = "abcdefghjkmnpqrstuvwxyz23456789";
  let t = "";
  for (let i = 0; i < 12; i++) t += signes[crypto.randomInt(signes.length)] + (i % 4 === 3 && i < 11 ? "-" : "");
  return t;
}
function sansAccents(t) { return String(t || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase(); }
// identifiant = les initiales de la fiche (arbitrage du 16/11/2026 au soir) ; à défaut prénom.nom
function baseIdentifiant(p) {
  const net = (t) => sansAccents(t).replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return net(p.initiales).replace(/-/g, "") || [net(p.prenom), net(p.nom)].filter(Boolean).join(".") || "personne";
}
const attendre = (ms) => new Promise((x) => setTimeout(x, ms));
// 19/11/2026 : les droits d'une personne se déduisent de ses profils allumés.
//   outil ouvert (1) = outil « libre » (ouvert à tous) OU présent dans un profil allumé OU profil « tous » (admin général) allumé ;
//   niveau 2 = lecture payante, si la colonne « version payante » est allumée et que l'outil en a une (FUSION, MONETA).
//   19/11/2026 (soir) : l'admin général emporte tout, version payante comprise.
function calculerAcces(profils, payante, outils) {
  const tous = profils.some((p) => p.tous);
  if (tous) payante = true;
  const ouverts = new Set();
  for (const p of profils) for (const id of (typeof p.outils === "string" ? JSON.parse(p.outils) : (p.outils || []))) ouverts.add(id);
  const acces = {};
  for (const o of outils) if (o.libre || tous || ouverts.has(o.id)) acces[o.id] = payante && o.premium ? 2 : 1;
  return acces;
}
async function accesDe(sql, personneId) {
  const [profils, pers, outils] = await Promise.all([
    sql`SELECT p.tous, p.outils FROM carnet_profil_personne pp JOIN carnet_profil p ON p.id = pp.profil WHERE pp.personne_id = ${personneId}`,
    sql`SELECT version_payante FROM carnet_personne WHERE id = ${personneId}`,
    sql`SELECT id, premium, libre FROM carnet_outil`]);
  return calculerAcces(profils, !!(pers.length && pers[0].version_payante), outils);
}
// 26/11/2026 : la colonne « actes et taxes » ouvre le dossier des actes taxés (contrôle des calculateurs) ; l'admin général l'emporte.
//   La colonne est lue par to_jsonb : tant que le script carnet_lot4 n'a pas été joué dans Neon, la réponse est simplement « non ».
async function actesTaxesDe(sql, personneId) {
  const [adm, pers] = await Promise.all([
    sql`SELECT 1 FROM carnet_profil_personne pp JOIN carnet_profil p ON p.id = pp.profil WHERE pp.personne_id = ${personneId} AND p.tous LIMIT 1`,
    sql`SELECT (to_jsonb(carnet_personne)->>'actes_taxes') AS actes_taxes FROM carnet_personne WHERE id = ${personneId}`]);
  return adm.length > 0 || !!(pers.length && pers[0].actes_taxes === "true");
}
// profils allumés d'office à la création d'une fiche (19/11/2026) : associé = les cinq profils métiers et Premium ; les autres : aucun
const PROFILS_ASSOCIE = ["immobilier", "famille", "affaires", "international", "premium"];
async function profilsParDefaut(sql, personneId, categorie) {
  if (categorie !== "associe") return;
  try {
    for (const pr of PROFILS_ASSOCIE)
      await sql`INSERT INTO carnet_profil_personne (personne_id, profil) SELECT ${personneId}, id FROM carnet_profil WHERE id = ${pr} ON CONFLICT DO NOTHING`;
  } catch { /* tables des profils pas encore créées : rien à faire */ }
}
// adresse de l'administrateur, rendue aux personnes pour leurs demandes d'accès (variable CARNET_CONTACT, sinon la fiche de JFD)
async function contactAdmin(sql) {
  if (process.env.CARNET_CONTACT) return texte(process.env.CARNET_CONTACT, 200);
  try {
    const r = await sql`SELECT courriel_c FROM carnet_personne WHERE actif AND categorie = 'associe' AND lower(nom) = 'dumetz' ORDER BY id LIMIT 1`;
    return r.length ? dechiffrer(r[0].courriel_c) : "";
  } catch { return ""; }
}
class Refus extends Error { constructor(code, message) { super(message); this.code = code; } }

// actions ouvertes aux personnes (sans session d'administrateur)
const actionsPersonnes = {
  async p_connexion(sql, c) {
    const identifiant = texte(c.identifiant, 120).toLowerCase(), mdp = String(c.mdp || "");
    const refus = async () => { await attendre(600); throw new Refus(401, "Identifiant ou mot de passe incorrect."); };
    if (!identifiant || !mdp) return refus();
    const r = await sql`SELECT c.*, p.prenom, p.nom, p.actif FROM carnet_compte c JOIN carnet_personne p ON p.id = c.personne_id WHERE c.identifiant = ${identifiant}`;
    if (!r.length) { hacherMdp(mdp, "inconnu"); return refus(); }
    const k = r[0];
    if (k.bloque_jusqua && new Date(k.bloque_jusqua).getTime() > Date.now()) {
      const min = Math.ceil((new Date(k.bloque_jusqua).getTime() - Date.now()) / 60000);
      throw new Refus(429, `Trop d'essais : réessayez dans ${min} minute${min > 1 ? "s" : ""}.`);
    }
    if (!mdpEgal(mdp, k.sel, k.empreinte)) {
      const echecs = (k.echecs || 0) + 1;
      if (echecs >= ESSAIS_MAX) await sql`UPDATE carnet_compte SET echecs = 0, bloque_jusqua = ${new Date(Date.now() + BLOCAGE_MS).toISOString()}::timestamptz WHERE personne_id = ${k.personne_id}`;
      else await sql`UPDATE carnet_compte SET echecs = ${echecs}::int WHERE personne_id = ${k.personne_id}`;
      return refus();
    }
    if (!k.actif) return refus();
    if (k.provisoire && k.expire_le && new Date(k.expire_le).getTime() < Date.now())
      throw new Refus(401, "Ce mot de passe provisoire a expiré : demandez-en un nouveau.");
    await sql`UPDATE carnet_compte SET echecs = 0, bloque_jusqua = NULL, derniere_connexion = NOW() WHERE personne_id = ${k.personne_id}`;
    const j = creerJetonPersonne(k.personne_id);
    return { jeton: j.jeton, expire: j.expire, provisoire: !!k.provisoire, personne: { prenom: k.prenom, nom: k.nom }, contact: await contactAdmin(sql),
      acces: k.provisoire ? {} : await accesDe(sql, k.personne_id), actes_taxes: k.provisoire ? false : await actesTaxesDe(sql, k.personne_id) };
  },

  // remplacement du mot de passe par la personne elle-même (obligatoire tant qu'il est provisoire)
  async p_changer(sql, c) {
    const j = lireJetonPersonne(c.jeton);
    if (!j) throw new Refus(401, "Connexion expirée, reconnectez-vous.");
    const ancien = String(c.ancien || ""), nouveau = String(c.nouveau || "");
    const r = await sql`SELECT c.*, p.actif FROM carnet_compte c JOIN carnet_personne p ON p.id = c.personne_id WHERE c.personne_id = ${j.id}`;
    if (!r.length || !r[0].actif || j.emis < new Date(r[0].mdp_le).getTime() - 2000) throw new Refus(401, "Connexion expirée, reconnectez-vous.");
    if (!mdpEgal(ancien, r[0].sel, r[0].empreinte)) { await attendre(600); throw new Refus(400, "Le mot de passe actuel est incorrect."); }
    if (nouveau.length < MDP_LONGUEUR_MIN) throw new Refus(400, `Le nouveau mot de passe doit compter au moins ${MDP_LONGUEUR_MIN} caractères.`);
    if (nouveau.length > 200) throw new Refus(400, "Le nouveau mot de passe est trop long.");
    if (nouveau === ancien) throw new Refus(400, "Le nouveau mot de passe doit être différent de l'ancien.");
    if (r[0].identifiant.length >= 4 && sansAccents(nouveau).includes(r[0].identifiant)) throw new Refus(400, "Le mot de passe ne doit pas contenir votre identifiant.");
    const sel = crypto.randomBytes(16).toString("base64url");
    await sql`UPDATE carnet_compte SET sel = ${sel}, empreinte = ${hacherMdp(nouveau, sel)}, provisoire = FALSE, expire_le = NULL,
              mdp_le = NOW(), demande_le = NULL, echecs = 0, bloque_jusqua = NULL WHERE personne_id = ${j.id}`;
    const p = await sql`SELECT prenom, nom FROM carnet_personne WHERE id = ${j.id}`;
    await journaliser(sql, j.id, nomComplet(p[0]), "mot de passe personnalisé", null, "personne");
    const n = creerJetonPersonne(j.id);
    return { ok: true, jeton: n.jeton, expire: n.expire, provisoire: false, contact: await contactAdmin(sql), acces: await accesDe(sql, j.id), actes_taxes: await actesTaxesDe(sql, j.id) };
  },

  // droits de la personne connectée : appelé par la page d'accueil et par chaque outil à son ouverture
  async p_moi(sql, c) {
    const j = lireJetonPersonne(c.jeton);
    if (!j) throw new Refus(401, "Connexion expirée, reconnectez-vous.");
    const r = await sql`SELECT c.provisoire, c.mdp_le, p.prenom, p.nom, p.actif FROM carnet_compte c JOIN carnet_personne p ON p.id = c.personne_id WHERE c.personne_id = ${j.id}`;
    if (!r.length || !r[0].actif || j.emis < new Date(r[0].mdp_le).getTime() - 2000) throw new Refus(401, "Connexion expirée, reconnectez-vous.");
    return { provisoire: !!r[0].provisoire, personne: { prenom: r[0].prenom, nom: r[0].nom }, contact: await contactAdmin(sql), acces: r[0].provisoire ? {} : await accesDe(sql, j.id),
      actes_taxes: r[0].provisoire ? false : await actesTaxesDe(sql, j.id) };
  },

  // « mot de passe oublié » : la demande est notée, JFD réinitialise depuis le tableau des accès (même réponse que l'identifiant existe ou non)
  async p_oubli(sql, c) {
    const identifiant = texte(c.identifiant, 120).toLowerCase();
    await attendre(400);
    if (identifiant) await sql`UPDATE carnet_compte SET demande_le = NOW() WHERE identifiant = ${identifiant}`;
    return { ok: true, contact: await contactAdmin(sql) };
  },
};

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
    id: p.id, nom: p.nom, prenom: p.prenom, civilite: p.civilite || "", categorie: p.categorie, initiales: p.initiales || "", sans_signature: !!p.sans_signature,
    actif: p.actif, inactif_le: p.inactif_le, maj_le: p.maj_le,
    ligne2: dechiffrer(p.ligne2_c), couleur: p.couleur || COULEURS[0], homonyme_verifie: !!p.homonyme_verifie,
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
    fonction: texte(c.fonction, 120), service: texte(c.service, 160), telephone: texte(c.telephone, 40), portable: texte(c.portable, 40), sans_signature: c.sans_signature === true || c.sans_signature === "true", ligne2: texte(c.ligne2, 120), couleur: COULEURS.includes(c.couleur) ? c.couleur : COULEURS[0], courriel: texte(c.courriel, 200).toLowerCase(),
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
      const r = await sql`INSERT INTO carnet_personne (nom, prenom, civilite, categorie, initiales, site_id, sans_signature, fonction_c, service_c, ligne2_c, couleur, telephone_c, portable_c, courriel_c, courriel_empreinte)
        VALUES (${p.nom}, ${p.prenom}, ${p.civilite}, ${p.categorie}, ${p.initiales}, ${p.site_id}, ${p.sans_signature},
                ${chiffrer(p.fonction)}, ${chiffrer(p.service)}, ${chiffrer(p.ligne2)}, ${p.couleur}, ${chiffrer(p.telephone)}, ${chiffrer(p.portable)}, ${chiffrer(p.courriel)}, ${emp}) RETURNING id`;
      await journaliser(sql, r[0].id, nomComplet(p), "création", null);
      await profilsParDefaut(sql, r[0].id, p.categorie);
      return { ok: true, id: r[0].id };
    }
    const avant = (await personnes(sql, true)).find((x) => x.id === id);
    if (!avant) throw new Error("Personne introuvable.");
    if (c.service === undefined) p.service = avant.service;   // 05/11 : le champ « service » n'est plus saisi à l'écran, sa valeur est gardée
    const modifies = Object.keys(LIBELLES).filter((k) => String(avant[k] == null ? "" : avant[k]) !== String(p[k] == null ? "" : p[k]));
    if (!modifies.length) return { ok: true, id, inchange: true };
    await sql`UPDATE carnet_personne SET nom = ${p.nom}, prenom = ${p.prenom}, civilite = ${p.civilite}, categorie = ${p.categorie},
              initiales = ${p.initiales}, site_id = ${p.site_id}, sans_signature = ${p.sans_signature}, fonction_c = ${chiffrer(p.fonction)}, service_c = ${chiffrer(p.service)}, ligne2_c = ${chiffrer(p.ligne2)}, couleur = ${p.couleur},
              telephone_c = ${chiffrer(p.telephone)}, portable_c = ${chiffrer(p.portable)}, courriel_c = ${chiffrer(p.courriel)}, courriel_empreinte = ${emp}, maj_le = NOW()
              WHERE id = ${id}`;
    await journaliser(sql, id, nomComplet(p), "correction", modifies.map((k) => LIBELLES[k]).join(", "));
    return { ok: true, id };
  },

  // 05/11 : contrôle des doublons — « ce n'est pas un doublon » : les personnes désignées sortent de l'encadré des homonymes
  async homonyme_ok(sql, c) {
    const ids = (Array.isArray(c.ids) ? c.ids : []).map((x) => parseInt(x, 10)).filter(Number.isFinite);
    if (ids.length < 2) throw new Error("Il faut au moins deux personnes.");
    const r = await sql`UPDATE carnet_personne SET homonyme_verifie = TRUE WHERE id = ANY(${ids}) RETURNING id, prenom, nom`;
    for (const x of r) await journaliser(sql, x.id, nomComplet(x), "homonyme vérifié (pas un doublon)", null);
    return { ok: true };
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
      const r = await sql`INSERT INTO carnet_personne (nom, prenom, civilite, categorie, initiales, site_id, sans_signature, fonction_c, service_c, telephone_c, portable_c, courriel_c, courriel_empreinte)
        VALUES (${p.nom}, ${p.prenom}, ${p.civilite}, ${p.categorie}, ${p.initiales}, ${p.site_id}, ${p.sans_signature},
                ${chiffrer(p.fonction)}, ${chiffrer(p.service)}, ${chiffrer(p.telephone)}, ${chiffrer(p.portable)}, ${chiffrer(p.courriel)}, ${emp}) RETURNING id`;
      await journaliser(sql, r[0].id, nomComplet(p), "création", null, c.origine === "ronde" ? "ronde" : "import");
      await profilsParDefaut(sql, r[0].id, p.categorie);
      crees++;
    }
    return { ok: true, crees, ecartes };
  },

  // ronde avec le Drive lancée à la main depuis l'écran (simulation possible : rien n'est écrit)
  async ronde(sql, c) {
    return { ok: true, bilan: await ronde({ sql, personnes, journaliser, importer: actions.importer }, { simulation: !!c.simulation, origine: "ronde" }) };
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
  // ---------- lot 3 (16/11/2026, refondu le 19/11/2026) : profils d'accès, version payante, comptes ----------
  async acces_lire(sql) {
    const [outils, profils, pers, liens, comptes] = await Promise.all([
      sql`SELECT id, nom, premium, libre FROM carnet_outil ORDER BY ordre, nom`,
      sql`SELECT id, nom, tous, outils FROM carnet_profil ORDER BY ordre, nom`,
      sql`SELECT id, nom, prenom, civilite, categorie, fonction_c, courriel_c, version_payante, (to_jsonb(carnet_personne)->>'actes_taxes') AS actes_taxes FROM carnet_personne WHERE actif ORDER BY nom, prenom`,
      sql`SELECT personne_id, profil FROM carnet_profil_personne`,
      sql`SELECT personne_id, identifiant, provisoire, expire_le, derniere_connexion, demande_le, bloque_jusqua FROM carnet_compte`,
    ]);
    return {
      outils,
      profils: profils.map((x) => ({ id: x.id, nom: x.nom, tous: !!x.tous, outils: typeof x.outils === "string" ? JSON.parse(x.outils) : (x.outils || []) })),
      personnes: pers.map((p) => ({ id: p.id, nom: p.nom, prenom: p.prenom, civilite: p.civilite || "", categorie: p.categorie, fonction: dechiffrer(p.fonction_c),
        courriel: dechiffrer(p.courriel_c), payante: !!p.version_payante, actes: p.actes_taxes === "true" })),
      liens, comptes,
    };
  },

  // un interrupteur de profil : allumé (actif = true) ou éteint ; effet immédiat, même sur une connexion en cours
  async profil_poser(sql, c) {
    const pid = parseInt(c.personne_id, 10), profil = texte(c.profil, 40), actif = c.actif === true || c.actif === "true";
    const [p, pr] = await Promise.all([sql`SELECT prenom, nom FROM carnet_personne WHERE id = ${pid}`, sql`SELECT nom FROM carnet_profil WHERE id = ${profil}`]);
    if (!p.length) throw new Error("Personne introuvable.");
    if (!pr.length) throw new Error("Profil inconnu : " + profil);
    if (actif) await sql`INSERT INTO carnet_profil_personne (personne_id, profil) VALUES (${pid}, ${profil}) ON CONFLICT DO NOTHING`;
    else await sql`DELETE FROM carnet_profil_personne WHERE personne_id = ${pid} AND profil = ${profil}`;
    await journaliser(sql, pid, nomComplet(p[0]), actif ? "profil allumé" : "profil éteint", pr[0].nom);
    return { ok: true };
  },

  // la colonne « version payante » : ouvre la lecture payante de FUSION et MONETA (si la personne a accès à l'outil)
  async payante_poser(sql, c) {
    const pid = parseInt(c.personne_id, 10), actif = c.actif === true || c.actif === "true";
    const p = await sql`UPDATE carnet_personne SET version_payante = ${actif} WHERE id = ${pid} RETURNING prenom, nom`;
    if (!p.length) throw new Error("Personne introuvable.");
    await journaliser(sql, pid, nomComplet(p[0]), actif ? "version payante ouverte" : "version payante fermée", null);
    return { ok: true };
  },

  // la colonne « actes et taxes » (26/11/2026) : ouvre le dossier des actes taxés, à part des profils
  async actes_taxes_poser(sql, c) {
    const pid = parseInt(c.personne_id, 10), actif = c.actif === true || c.actif === "true";
    let p;
    try { p = await sql`UPDATE carnet_personne SET actes_taxes = ${actif} WHERE id = ${pid} RETURNING prenom, nom`; }
    catch (e) { throw new Error("La colonne « actes et taxes » n'existe pas encore : exécutez le script carnet_lot4_profils.sql dans Neon."); }
    if (!p.length) throw new Error("Personne introuvable.");
    await journaliser(sql, pid, nomComplet(p[0]), actif ? "actes et taxes ouvert" : "actes et taxes fermé", null);
    return { ok: true };
  },

  // ouverture du compte ou réinitialisation : un mot de passe provisoire est fabriqué et rendu UNE fois (pour le brouillon de courriel) ;
  // seule son empreinte est gardée. L'identifiant, une fois attribué, ne change plus.
  async compte_ouvrir(sql, c) {
    const pid = parseInt(c.personne_id, 10);
    const p = await sql`SELECT id, prenom, nom, civilite, initiales, actif, courriel_c FROM carnet_personne WHERE id = ${pid}`;
    if (!p.length) throw new Error("Personne introuvable.");
    if (!p[0].actif) throw new Error("Cette personne est inactive : pas de compte.");
    const existant = await sql`SELECT identifiant FROM carnet_compte WHERE personne_id = ${pid}`;
    const mdp = mdpProvisoire(), sel = crypto.randomBytes(16).toString("base64url");
    const expire = new Date(Date.now() + DUREE_PROVISOIRE_MS).toISOString();
    let identifiant;
    if (existant.length) {
      identifiant = existant[0].identifiant;
      await sql`UPDATE carnet_compte SET sel = ${sel}, empreinte = ${hacherMdp(mdp, sel)}, provisoire = TRUE, expire_le = ${expire}::timestamptz,
                mdp_le = NOW(), echecs = 0, bloque_jusqua = NULL, demande_le = NULL WHERE personne_id = ${pid}`;
    } else {
      const base = baseIdentifiant(p[0]);
      const pris = (await sql`SELECT identifiant FROM carnet_compte WHERE identifiant LIKE ${base + "%"}`).map((x) => x.identifiant);
      identifiant = base;
      for (let n = 2; pris.includes(identifiant); n++) identifiant = base + n;
      await sql`INSERT INTO carnet_compte (personne_id, identifiant, sel, empreinte, provisoire, expire_le)
                VALUES (${pid}, ${identifiant}, ${sel}, ${hacherMdp(mdp, sel)}, TRUE, ${expire}::timestamptz)`;
    }
    await journaliser(sql, pid, nomComplet(p[0]), existant.length ? "mot de passe réinitialisé" : "ouverture du compte", null);
    return { ok: true, nouveau: !existant.length, identifiant, mdp, expire_le: expire, courriel: dechiffrer(p[0].courriel_c), prenom: p[0].prenom, nom: p[0].nom, civilite: p[0].civilite || "" };
  },
  // fermeture du compte : la personne ne peut plus se connecter ; ses profils restent notés dans le tableau
  async compte_fermer(sql, c) {
    const pid = parseInt(c.personne_id, 10);
    const r = await sql`DELETE FROM carnet_compte WHERE personne_id = ${pid} RETURNING identifiant`;
    if (r.length) {
      const p = await sql`SELECT prenom, nom FROM carnet_personne WHERE id = ${pid}`;
      await journaliser(sql, pid, p.length ? nomComplet(p[0]) : r[0].identifiant, "fermeture du compte", null);
    }
    return { ok: true };
  },
};

// ---------- point d'entrée ----------
module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  const fin = (code, obj) => { res.statusCode = code; res.end(JSON.stringify(obj)); };

  // lot 3 : la page d'accueil et les outils connectent les personnes depuis le navigateur ; seules les origines listées sont admises,
  // et l'en-tête Authorization n'est pas autorisé d'une autre origine (l'écran d'administration reste réservé à CARNET lui-même)
  const origine = String(req.headers.origin || "");
  res.setHeader("Vary", "Origin");
  if (origine && ORIGINES_PERSONNES.includes(origine)) {
    res.setHeader("Access-Control-Allow-Origin", origine);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Max-Age", "600");
  }
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }

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

  // ----- ronde hebdomadaire automatique (tâche planifiée Vercel, dimanche soir) -----
  if (req.method === "GET" && q.action === "ronde") {
    const attendu = process.env.CRON_SECRET ? "Bearer " + process.env.CRON_SECRET : "";
    if (!attendu || String(req.headers["authorization"] || "") !== attendu) return fin(401, { erreur: "Non autorisé" });
    if (manque.length || !cleOk) return fin(503, { erreur: "CARNET n'est pas configuré." });
    const sql = neon(process.env.DATABASE_URL);
    try {
      return fin(200, { ok: true, bilan: await ronde({ sql, personnes, journaliser, importer: actions.importer }, { origine: "ronde" }) });
    } catch (e) {
      console.error("[carnet] ronde", e);
      try { await journaliser(sql, null, "Drive", "ronde hebdomadaire EN ÉCHEC", String(e.message || e).slice(0, 300), "ronde"); } catch {}
      return fin(500, { erreur: e.message || "Erreur serveur" });
    }
  }

  if (req.method !== "POST") return fin(405, { erreur: "Méthode non autorisée" });
  const corps = lireCorps(req);
  const action = texte(corps.action, 40);

  if (action === "etat") return fin(200, { pret: !manque.length && cleOk, manque, cle_invalide: !cleOk });
  if (manque.length) return fin(500, { erreur: "Variables absentes sur Vercel : " + manque.join(", ") });
  if (!cleOk) return fin(500, { erreur: "CARNET_CLE_CHIFFREMENT invalide : il faut 32 octets en base64." });

  if (actionsPersonnes[action]) {
    try { return fin(200, await actionsPersonnes[action](neon(process.env.DATABASE_URL), corps)); }
    catch (e) {
      if (e instanceof Refus) return fin(e.code, { erreur: e.message });
      console.error("[carnet]", action, e);
      return fin(500, { erreur: "Erreur serveur" });
    }
  }

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
