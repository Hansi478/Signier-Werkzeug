// Erzeugt Handbuch.pdf aus docs/handbuch_quelle.html (Version und Repository aus signier_werkzeug.py).
// Aufruf im Wurzelordner: node docs/handbuch_pdf.js
// Braucht playwright-core (npm) und Chromium; Pfad notfalls über CHROMIUM=… angeben.
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright-core");

const wurzel = path.join(__dirname, "..");
const quelltext = fs.readFileSync(path.join(wurzel, "signier_werkzeug.py"), "utf8");
const wert = name => (quelltext.match(new RegExp(`^${name} = "([^"]+)"`, "m")) || [])[1];
const version = wert("VERSION"), repo = wert("WERKZEUG_REPO");
if (!version || !repo) throw new Error("VERSION bzw. WERKZEUG_REPO nicht gefunden");
const html = fs.readFileSync(path.join(__dirname, "handbuch_quelle.html"), "utf8")
  .replaceAll("{{VERSION}}", version).replaceAll("{{REPO}}", repo);

(async () => {
  const browser = await chromium.launch(process.env.CHROMIUM ? {executablePath: process.env.CHROMIUM} : {});
  const seite = await browser.newPage();
  await seite.setContent(html, {waitUntil: "load"});
  await seite.pdf({path: path.join(wurzel, "Handbuch.pdf"), format: "A4", printBackground: false});
  await browser.close();
  console.log(`Handbuch.pdf erzeugt (Version ${version}).`);
})();
