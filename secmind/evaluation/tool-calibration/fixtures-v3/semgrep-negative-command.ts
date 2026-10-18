import * as child_process from "child_process";

export function runFixed() {
  return child_process.exec("/usr/bin/true");
}
