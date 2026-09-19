const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const Factory = await hre.ethers.getContractFactory("EvidenceLedger");
  const ledger = await Factory.deploy();
  await ledger.waitForDeployment();
  const address = await ledger.getAddress();

  const network = hre.network.name;
  console.log(`EvidenceLedger deployed to ${address} on network '${network}'`);

  const artifact = await hre.artifacts.readArtifact("EvidenceLedger");
  const outDir = path.join(__dirname, "..", "backend", "blockchain", "abi");
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "EvidenceLedger.json"), JSON.stringify(artifact.abi, null, 2));

  const deploymentInfo = { address, network, chainId: (await hre.ethers.provider.getNetwork()).chainId.toString() };
  fs.writeFileSync(
    path.join(__dirname, "..", "backend", "blockchain", "deployment.json"),
    JSON.stringify(deploymentInfo, null, 2)
  );
  console.log("Wrote ABI + deployment.json for backend to consume.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
