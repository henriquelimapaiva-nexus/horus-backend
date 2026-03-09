const bcrypt = require("bcrypt");

async function gerar() {
  const senha = "Nexus2903.,";
  const hash = await bcrypt.hash(senha, 10);
  console.log("HASH GERADO:");
  console.log(hash);
}

gerar().then(() => process.exit());