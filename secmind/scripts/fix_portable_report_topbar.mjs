import fs from "node:fs";

const file = process.argv[2];
if (!file) throw new Error("usage: node fix_portable_report_topbar.mjs <report.html>");
const marker = "data-secmind-portable-reader-fix=\"top-bar-scrollbar-gutter\"";
const style = `<style ${marker}>
.analytics-top-bar{width:calc(100% + var(--ds-gutter) + var(--ds-gutter))!important;margin-right:calc(0px - var(--ds-gutter))!important;margin-left:calc(0px - var(--ds-gutter))!important}
</style>`;
const html = fs.readFileSync(file, "utf8");
if (!html.includes("</head>")) throw new Error("portable report has no closing head");
if (!html.includes(marker)) {
  fs.writeFileSync(file, html.replace("</head>", `${style}\n</head>`), "utf8");
}
