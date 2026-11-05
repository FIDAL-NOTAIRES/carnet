// ============================================================
// CARNET — lib/ronde.js — ronde hebdomadaire avec le Drive (04/11/2026)
// Règle tranchée par JFD : (1) une personne présente dans un fichier du Drive mais absente de CARNET
// est créée dans CARNET ; (2) les deux fichiers sont ensuite RÉÉCRITS à partir de CARNET, qui l'emporte,
// avec les ACTIFS seulement ; correction silencieuse, sans alerte (le compte rendu va au journal).
// Accès : compte de service Google carnet-ronde@fidal-apps.iam.gserviceaccount.com, avec lequel JFD a
// partagé les deux fichiers en Éditeur (variable Vercel GOOGLE_COMPTE_SERVICE = contenu du fichier JSON de clé).
// ============================================================

const crypto = require("crypto");
const XLSX = require("xlsx");

const ID_ASSOCIES = process.env.CARNET_DRIVE_ASSOCIES || "17mxkue-qtRfe8wTPtpBbu6-oZDdjMNoN";            // feuille Google « Liste associés »
const ID_COLLABORATEURS = process.env.CARNET_DRIVE_COLLABORATEURS || "10amtSne7u3XTwvgdbznlUzv9CcvzokTO"; // fichier Excel « Liste_collaborateurs.xlsx »
const MIME_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

// ---------- jeton Google du compte de service (JWT signé RS256) ----------
async function jetonGoogle() {
  let cs;
  try { cs = JSON.parse(process.env.GOOGLE_COMPTE_SERVICE || ""); } catch { throw new Error("Variable GOOGLE_COMPTE_SERVICE absente ou illisible (contenu du fichier JSON de clé)."); }
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const maintenant = Math.floor(Date.now() / 1000);
  const entete = b64({ alg: "RS256", typ: "JWT" });
  const charge = b64({ iss: cs.client_email, scope: "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/spreadsheets",
    aud: cs.token_uri || "https://oauth2.googleapis.com/token", iat: maintenant, exp: maintenant + 3000 });
  const signature = crypto.createSign("RSA-SHA256").update(entete + "." + charge).sign(cs.private_key, "base64url");
  const r = await fetch(cs.token_uri || "https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: entete + "." + charge + "." + signature }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.access_token) throw new Error("Connexion Google refusée : " + (d.error_description || d.error || r.status));
  return { jeton: d.access_token, compte: cs.client_email };
}
async function appel(jeton, url, options = {}, quoi = "Google") {
  const r = await fetch(url, { ...options, headers: { Authorization: "Bearer " + jeton, ...(options.headers || {}) } });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    if (r.status === 404 || r.status === 403) throw new Error(`${quoi} : fichier introuvable ou non partagé avec le compte de service (${r.status}).`);
    throw new Error(`${quoi} : erreur ${r.status} ${t.slice(0, 200)}`);
  }
  return r;
}

// ---------- lecture des deux fichiers ----------
const cel = (v) => String(v == null ? "" : v).replace(/\s+/g, " ").trim();
const cleNom = (p) => (cel(p.nom) + "|" + cel(p.prenom)).toLowerCase();

async function lireAssocies(jeton) {
  const meta = await (await appel(jeton, `https://sheets.googleapis.com/v4/spreadsheets/${ID_ASSOCIES}?fields=sheets.properties.title`, {}, "Liste associés")).json();
  const feuille = meta.sheets[0].properties.title;
  const v = await (await appel(jeton, `https://sheets.googleapis.com/v4/spreadsheets/${ID_ASSOCIES}/values/${encodeURIComponent("'" + feuille + "'!A1:G500")}`, {}, "Liste associés")).json();
  const lignes = (v.values || []).map((l) => l.map(cel));
  const personnes = [];
  lignes.forEach((c, i) => {
    if (i === 0) return;                         // ligne de titres conservée telle quelle
    if (!c[0] || !/@/.test(c[2] || "")) return;
    personnes.push({ categorie: "associe", nom: c[0], prenom: c[1] || "", courriel: c[2], site: c[3] || "", fonction: "Notaire Associé",
      _site: { nom: c[3], code_postal: c[4], adresse: c[5], telephone: c[6] } });
  });
  return { feuille, personnes };
}
async function lireCollaborateurs(jeton) {
  const buf = Buffer.from(await (await appel(jeton, `https://www.googleapis.com/drive/v3/files/${ID_COLLABORATEURS}?alt=media&supportsAllDrives=true`, {}, "Liste_collaborateurs.xlsx")).arrayBuffer());
  const wb = XLSX.read(buf, { type: "buffer" });
  const nomFeuille = wb.SheetNames.find((n) => !/donn/i.test(n)) || wb.SheetNames[0];
  const lignes = XLSX.utils.sheet_to_json(wb.Sheets[nomFeuille], { header: 1, defval: "" }).map((l) => l.map(cel));
  const entete = lignes.find((l) => /^nom$/i.test(l[0] || "")) || ["nom", "prénom", "mail", "initiales", "site", "code postal", "adresse", "téléphone"];
  const personnes = [];
  lignes.forEach((c) => {
    if (!c[0] || /^nom$/i.test(c[0]) || !c[1]) return;
    personnes.push({ categorie: "collaborateur", nom: c[0], prenom: c[1], courriel: /@/.test(c[2]) ? c[2] : "", initiales: c[3], site: c[4],
      _site: { nom: c[4], code_postal: c[5], adresse: c[6], telephone: c[7] } });
  });
  return { wb, nomFeuille, entete, personnes };
}

// ---------- la ronde ----------
// outils = { sql, personnes(sql, inactifs), importer(sql, corps), journaliser(...) } fournis par api/carnet.js
// simulation = true : rien n'est écrit, ni dans CARNET ni dans le Drive ; on rend seulement le compte rendu
async function ronde(outils, { simulation = false, origine = "ronde" } = {}) {
  const { sql } = outils;
  const g = await jetonGoogle();
  const [A, C] = await Promise.all([lireAssocies(g.jeton), lireCollaborateurs(g.jeton)]);

  // 1) personnes du Drive absentes de CARNET (repérées par le courriel, à défaut par nom + prénom)
  let carnet = await outils.personnes(sql, true);
  const parCourriel = new Set(carnet.filter((p) => p.courriel).map((p) => p.courriel.toLowerCase()));
  const parNom = new Set(carnet.map(cleNom));
  const vus = new Set(), nouveaux = [];
  [...A.personnes, ...C.personnes].forEach((p) => {
    const c = (p.courriel || "").toLowerCase(), k = c || cleNom(p);
    if (vus.has(k)) return; vus.add(k);
    if (c ? parCourriel.has(c) : parNom.has(cleNom(p))) return;
    nouveaux.push(p);
  });
  let crees = 0, ecartes = [];
  if (nouveaux.length && !simulation) {
    const sites = {}; nouveaux.forEach((p) => { if (p._site && p._site.nom) sites[p._site.nom.toUpperCase()] = p._site; });
    const r = await outils.importer(sql, { personnes: nouveaux.map(({ _site, ...p }) => p), sites: Object.values(sites), origine });
    crees = r.crees; ecartes = r.ecartes;
    carnet = await outils.personnes(sql, true);
  }

  // 2) réécriture des deux fichiers à partir de CARNET (actifs seulement)
  const actifs = carnet.filter((p) => p.actif);
  const tri = (a, b) => a.nom.localeCompare(b.nom, "fr") || a.prenom.localeCompare(b.prenom, "fr");
  const tel = (p) => p.telephone || (p.site ? p.site.telephone : "");
  const assoc = actifs.filter((p) => p.categorie === "associe").sort(tri);
  // le fichier des collaborateurs contenait aussi quelques associés : on garde ceux qui y figuraient déjà
  const assocDejaDansCollab = new Set(C.personnes.map((p) => (p.courriel || "").toLowerCase()).filter(Boolean));
  const collab = actifs.filter((p) => p.categorie === "collaborateur" || (p.courriel && assocDejaDansCollab.has(p.courriel.toLowerCase()))).sort(tri);

  const lignesAssoc = assoc.map((p) => [p.nom, p.prenom, p.courriel, p.site ? p.site.nom : "", p.site ? p.site.code_postal : "", p.site ? p.site.adresse : "", tel(p)]);
  const lignesCollab = collab.map((p) => [p.nom, p.prenom, p.courriel || "-", p.initiales || "", p.site ? p.site.nom : "", p.site ? p.site.code_postal : "", p.site ? p.site.adresse : "", tel(p)]);

  const ecrits = new Set([...assoc, ...collab].map((p) => (p.courriel || cleNom(p)).toLowerCase()));
  if (simulation) nouveaux.forEach((p) => ecrits.add((p.courriel || cleNom(p)).toLowerCase()));   // en simulation, les nouveaux seraient créés puis réécrits
  const retires = [...A.personnes, ...C.personnes].filter((p) => !ecrits.has((p.courriel || cleNom(p)).toLowerCase()))
    .map((p) => `${p.prenom} ${p.nom}`).filter((x, i, t) => t.indexOf(x) === i);

  if (!simulation) {
    const plage = encodeURIComponent("'" + A.feuille + "'!A2:G500");
    await appel(g.jeton, `https://sheets.googleapis.com/v4/spreadsheets/${ID_ASSOCIES}/values/${plage}:clear`, { method: "POST" }, "Liste associés");
    if (lignesAssoc.length) {
      await appel(g.jeton, `https://sheets.googleapis.com/v4/spreadsheets/${ID_ASSOCIES}/values/${encodeURIComponent("'" + A.feuille + "'!A2")}?valueInputOption=RAW`,
        { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ values: lignesAssoc }) }, "Liste associés");
    }
    const ancienne = C.wb.Sheets[C.nomFeuille];
    const nouvelle = XLSX.utils.aoa_to_sheet([C.entete.slice(0, 8), ...lignesCollab]);
    if (ancienne && ancienne["!cols"]) nouvelle["!cols"] = ancienne["!cols"];   // largeurs de colonnes conservées
    if (ancienne && ancienne["!autofilter"]) nouvelle["!autofilter"] = { ref: "A1:H" + (lignesCollab.length + 1) };
    C.wb.Sheets[C.nomFeuille] = nouvelle;                                       // les autres feuilles (« Données ») restent intactes
    const sortie = XLSX.write(C.wb, { type: "buffer", bookType: "xlsx" });
    await appel(g.jeton, `https://www.googleapis.com/upload/drive/v3/files/${ID_COLLABORATEURS}?uploadType=media&supportsAllDrives=true`,
      { method: "PATCH", headers: { "Content-Type": MIME_XLSX }, body: sortie }, "Liste_collaborateurs.xlsx");
  }

  const bilan = { simulation, compte: g.compte, nouveaux: nouveaux.map((p) => `${p.prenom} ${p.nom} (${p.categorie === "associe" ? "associé" : "collaborateur"})`),
    crees, ecartes, retires,
    associes_ecrits: lignesAssoc.length + (simulation ? nouveaux.filter((p) => p.categorie === "associe").length : 0),
    collaborateurs_ecrits: lignesCollab.length + (simulation ? nouveaux.filter((p) => p.categorie !== "associe").length : 0) };
  if (!simulation) {
    await outils.journaliser(sql, null, "Drive", "ronde hebdomadaire",
      `${crees} créée(s) dans CARNET, ${lignesAssoc.length} associés et ${lignesCollab.length} collaborateurs réécrits, ${retires.length} retirée(s) des fichiers`, origine);
  }
  return bilan;
}

module.exports = { ronde };
