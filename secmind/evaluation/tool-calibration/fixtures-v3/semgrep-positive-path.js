const fs = require("fs");

function readItem(req) {
  return fs.readFileSync(req.query.filename, "utf8");
}
