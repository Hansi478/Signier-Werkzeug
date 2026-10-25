// Bildschirmfotos für das Handbuch (docs/bilder/*.png): startet das Werkzeug mit einem
// leeren Datenordner, legt Beispieldaten an (nur Platzhalter) und fotografiert die Bereiche.
// Aufruf im Wurzelordner: node docs/handbuch_bilder.js   (danach node docs/handbuch_pdf.js)
// Braucht Python mit „cryptography“, playwright-core (npm) und Chromium (CHROMIUM=…).
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const { chromium } = require("playwright-core");

const wurzel = path.join(__dirname, "..");
const bilder = path.join(__dirname, "bilder");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "handbuch-"));
const KW = "Beispiel-Kennwort-123";
const DATEN = "C:\\Users\\<Benutzer>\\AppData\\Roaming\\Signier-Werkzeug";
const warte = ms => new Promise(ok => setTimeout(ok, ms));

(async () => {
  fs.mkdirSync(bilder, {recursive: true});
  const server = spawn(process.env.PYTHON || "python3", ["signier_werkzeug.py", "--ohne-browser"], {
    cwd: wurzel, env: {...process.env, APPDATA: tmp, HOME: tmp, PYTHONDONTWRITEBYTECODE: "1"}, stdio: "ignore"});
  const adresse = path.join(tmp, "Signier-Werkzeug", "adresse.txt");
  for (let i = 0; i < 100 && !fs.existsSync(adresse); i++) await warte(100);
  const url = fs.readFileSync(adresse, "utf8").trim();
  // Beispielordner (eine „andere Software“)
  const ordner = path.join(tmp, "Beispiel-Software");
  fs.mkdirSync(path.join(ordner, "daten"), {recursive: true});
  fs.writeFileSync(path.join(ordner, "VERSION"), "1.4.0\n");
  fs.writeFileSync(path.join(ordner, "programm.py"), "print('Hallo')\n");
  fs.writeFileSync(path.join(ordner, "daten", "vorlage.txt"), "Beispiel\n");

  const browser = await chromium.launch(process.env.CHROMIUM ? {executablePath: process.env.CHROMIUM} : {});
  const seite = await browser.newPage({viewport: {width: 1100, height: 900}, deviceScaleFactor: 1.5});
  seite.on("dialog", d => d.accept());
  await seite.goto(url); await warte(800);
  const foto = async (name, ziel) => {
    await seite.evaluate(() => { const d = document.getElementById("datenpfad"); if (d) d.textContent = ""; });
    await seite.evaluate(t => { const d = document.getElementById("datenpfad"); if (d) d.textContent = t; }, DATEN);
    const el = ziel ? seite.locator(ziel).first() : seite;
    await el.screenshot({path: path.join(bilder, name + ".png"), ...(ziel ? {} : {fullPage: false})});
  };
  const api = (name, daten) => seite.evaluate(([n, d]) => api(n, d), [name, daten || {}]);
  const reiter = async r => { await seite.click(`[data-reiter="${r}"]`); await warte(300); };

  // Profile und Schlüssel
  let z = await api("profil_speichern", {name: "Speedrace-Dashboard", regel: "speedrace", repo: "Besitzer/Dashboard"});
  const sr = z.profile[z.profile.length - 1].id;
  await api("schluessel_neu", {id: sr, kennwort: KW});
  z = await api("profil_speichern", {name: "Beispiel-Software", regel: "alle", repo: "Besitzer/Beispiel", ausschluss: "logs/*\n*.log"});
  const bs = z.profile[z.profile.length - 1].id;
  await api("schluessel_neu", {id: bs, kennwort: KW});
  await seite.reload(); await warte(800);
  await seite.screenshot({path: path.join(bilder, "01_start.png"), clip: {x: 0, y: 0, width: 1100, height: 450}});

  await reiter("profile");
  await seite.click(`[data-bearb="${bs}"]`); await warte(300);
  await foto("03_profil_liste", "#r-profile .karte");
  await foto("04_profil_bearbeiten", "#bearbeiten");
  await seite.click("#b-prompt"); await warte(800);
  await seite.evaluate(() => document.getElementById("b-prompt-text").scrollTop = 0);
  await foto("05_prompt", "#b-einbindung");
  await seite.click("#neu-allgemein"); await warte(300);
  await foto("06_profil_neu", "#bearbeiten");
  await seite.click("#b-abbrechen");

  await reiter("github");
  await seite.evaluate(() => { document.getElementById("g-stand").textContent =   // so wie unter Windows
    "Noch kein Token gespeichert. Neues Token wird gespeichert: Windows-DPAPI (dauerhaft)."; });
  await foto("07_github", "#r-github");

  // Signieren
  await reiter("signieren");
  await seite.selectOption("#s-profil", sr); await warte(200);
  await seite.evaluate(() => {   // Beispiel einer geprüften Paketliste (ohne GitHub)
    document.getElementById("s-pakete-info").innerHTML = 'Programmversion <b>1.8.12</b>, Prüfsumme <span class="mono">3f7a…c21e</span>, '
      + 'cloudflared <b>2026.10.0</b>. <br>Debian trixie: Stand 24.10.2026 (bisher 26.09.2026). Änderungen gegenüber v1.8.12:<ul><li class="mono">pypdf 6.20.1 → 6.21.1</li>'
      + '<li class="mono">cloudflared 2026.9.1 → 2026.10.0</li></ul>';
    document.getElementById("s-pakete-los-zeile").classList.remove("versteckt");
  });
  await foto("08_signieren", "#r-signieren .karte");
  await seite.selectOption("#s-profil", bs); await warte(200);
  await seite.click("#r-signieren details summary");
  await seite.fill("#s-ordner", "C:\\Programme\\Beispiel-Software");
  await seite.evaluate(() => { kennwort("Beispiel-Software: Ordner C:\\Programme\\Beispiel-Software signieren."); });
  await warte(300);
  await foto("09_kennwort", "#kw-dialog .karte");
  await seite.click("#kw-abbr");
  const r = await api("signieren_ordner", {id: bs, kennwort: KW, ordner});
  await seite.evaluate(m => status("s-status", "ok", "✅ " + esc(m)), r.meldung.replace(/Version .*?,/, "Version 1.4.0,"));
  await foto("10_signiert", "#r-signieren .karte");

  // Prüfen
  await reiter("pruefen");
  await seite.selectOption("#p-profil", bs);
  await seite.fill("#p-ordner", ordner);
  const platzhalter = () => seite.fill("#p-ordner", "C:\\Programme\\Beispiel-Software");
  await seite.click("#p-ordner-los"); await warte(800); await platzhalter();
  await foto("11_pruefen_ok", "#r-pruefen .karte");
  fs.writeFileSync(path.join(ordner, "programm.py"), "print('verändert')\n");
  fs.writeFileSync(path.join(ordner, "zusatz.py"), "import os\n");
  await seite.fill("#p-ordner", ordner);
  await seite.click("#p-ordner-los"); await warte(800); await platzhalter();
  await foto("12_pruefen_fehler", "#r-pruefen .karte");

  // QNAP
  await reiter("qnap"); await warte(500);
  for (const [id, w] of [["q-host", "192.0.2.10"], ["q-benutzer", "admin"], ["q-ordner", "/share/Container/dashboard"],
                         ["q-adresse", "http://192.0.2.10:8080/"]]) await seite.fill("#" + id, w);
  await seite.selectOption("#q-quelle", sr);
  await seite.click("#q-speichern"); await warte(500);
  await foto("13_qnap_profil", "#r-qnap .karte");
  await seite.selectOption("#q-ablauf", "installieren"); await warte(300);
  await seite.click("#q-beginnen"); await warte(600);
  await foto("14_qnap_ablauf", "#q-schritte .karte");
  await seite.click("#q-schritte .karte button"); await warte(600);   // Vorbereitung gelesen
  await foto("15_qnap_schritt", "#qs-1");

  await browser.close();
  server.kill();
  fs.rmSync(tmp, {recursive: true, force: true});
  console.log("Bilder in docs/bilder/ erzeugt.");
})().catch(e => { console.error(e); process.exit(1); });
