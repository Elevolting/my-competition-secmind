const fs = require("fs");

function read(request) {
  const file = request.query.file;
  return fs.readFile(file, () => undefined);
}
