import { exec } from "child_process";

function run(request: { query: { command: string } }) {
  const command = request.query.command;
  return exec(command);
}
