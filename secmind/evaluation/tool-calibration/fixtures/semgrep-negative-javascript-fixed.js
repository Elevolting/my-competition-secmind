const fs = require("fs");

function read() {
  return fs.readFile("/srv/app/README.md", () => undefined);
}
