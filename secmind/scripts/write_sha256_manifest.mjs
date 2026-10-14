import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [directory, outputName = "SHA256SUMS.txt"] = process.argv.slice(2);
if (!directory) throw new Error("usage: node write_sha256_manifest.mjs <directory> [output-name]");
const outputPath = path.join(directory, outputName);
const files = fs
  .readdirSync(directory, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name !== outputName)
  .map((entry) => entry.name)
  .sort((left, right) => left.localeCompare(right, "zh-CN"));
const lines = files.map((name) => {
  const bytes = fs.readFileSync(path.join(directory, name));
  return `${crypto.createHash("sha256").update(bytes).digest("hex")}  ${name}`;
});
fs.writeFileSync(outputPath, `${lines.join("\n")}\n`, "utf8");
