import * as child_process from "child_process";

export function run(req: any) {
  const command = req.body.command;
  return child_process.exec(command);
}
