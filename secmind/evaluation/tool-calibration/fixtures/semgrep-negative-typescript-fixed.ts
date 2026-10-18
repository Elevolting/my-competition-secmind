import { execFile } from "child_process";

function run() {
  return execFile("/usr/bin/true", []);
}
