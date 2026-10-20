// Erzeugt Handbuch.pdf aus docs/handbuch_quelle.html und docs/bilder/ (Version und Repository
// aus signier_werkzeug.py). Aufruf im Wurzelordner: node docs/handbuch_pdf.js
// Braucht playwright-core (npm) und Chromium; Pfad notfalls über CHROMIUM=… angeben.
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const { chromium } = require("playwright-core");

const wurzel = path.join(__dirname, "..");
const quelltext = fs.readFileSync(path.join(wurzel, "signier_werkzeug.py"), "utf8");
const wert = name => (quelltext.match(new RegExp(`^${name} = "([^"]+)"`, "m")) || [])[1];
const version = wert("VERSION"), repo = wert("WERKZEUG_REPO");
if (!version || !repo) throw new Error("VERSION bzw. WERKZEUG_REPO nicht gefunden");
const html = fs.readFileSync(path.join(__dirname, "handbuch_quelle.html"), "utf8")
  .replaceAll("{{VERSION}}", version).replaceAll("{{REPO}}", repo);
const tmp = path.join(__dirname, ".handbuch_druck.html");   // neben bilder/, damit die Bilder gefunden werden

(async () => {
  fs.writeFileSync(tmp, html);
  const browser = await chromium.launch(process.env.CHROMIUM ? {executablePath: process.env.CHROMIUM} : {});
  try {
    const seite = await browser.newPage();
    await seite.goto(pathToFileURL(tmp).href, {waitUntil: "load"});
    await seite.pdf({path: path.join(wurzel, "Handbuch.pdf"), format: "A4", printBackground: true,
      displayHeaderFooter: true, headerTemplate: "<span></span>",
      footerTemplate: `<div style="font:8px system-ui,sans-serif;color:#64748b;width:100%;padding:0 16mm;display:flex;justify-content:space-between">
        <span>Signier-Werkzeug ${version} – Handbuch</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`,
      margin: {top: "16mm", bottom: "18mm", left: "16mm", right: "16mm"}});
  } finally {
    await browser.close();
    fs.rmSync(tmp, {force: true});
  }
  console.log(`Handbuch.pdf erzeugt (Version ${version}).`);
})();
