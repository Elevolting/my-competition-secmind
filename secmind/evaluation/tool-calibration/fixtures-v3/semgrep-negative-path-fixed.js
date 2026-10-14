const fs = require("fs");

function readHealth() {
  return fs.readFileSync("/etc/hostname", "utf8");
}
