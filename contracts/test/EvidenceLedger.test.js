const { expect } = require("chai");
const { ethers } = require("hardhat");
const crypto = require("crypto");

function hash(s) {
  return "0x" + crypto.createHash("sha256").update(s).digest("hex");
}

describe("EvidenceLedger", function () {
  let ledger, owner, other;

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("EvidenceLedger");
    ledger = await Factory.deploy();
    await ledger.waitForDeployment();
  });

  it("registers a case and reads it back correctly", async function () {
    const merkleRoot = hash("merkle-root-1");
    const reportHash = hash("report-1");

    await expect(ledger.registerCase("VK-2026-0001", merkleRoot, reportHash))
      .to.emit(ledger, "CaseRegistered");

    const rec = await ledger.getCase("VK-2026-0001");
    expect(rec[0]).to.equal(merkleRoot);
    expect(rec[1]).to.equal(reportHash);
    expect(rec[3]).to.equal(owner.address);
  });

  it("rejects an empty case ID", async function () {
    await expect(ledger.registerCase("", hash("a"), hash("b"))).to.be.revertedWithCustomError(
      ledger,
      "EmptyCaseId"
    );
  });

  it("rejects re-registering the same case ID", async function () {
    await ledger.registerCase("VK-DUP", hash("a"), hash("b"));
    await expect(ledger.registerCase("VK-DUP", hash("c"), hash("d"))).to.be.revertedWithCustomError(
      ledger,
      "CaseAlreadyRegistered"
    );
  });

  it("reverts getCase() for an unknown case ID", async function () {
    await expect(ledger.getCase("VK-DOES-NOT-EXIST")).to.be.revertedWithCustomError(
      ledger,
      "CaseNotFound"
    );
  });

  it("supports multiple independent cases", async function () {
    await ledger.registerCase("VK-A", hash("a1"), hash("a2"));
    await ledger.registerCase("VK-B", hash("b1"), hash("b2"));
    const a = await ledger.getCase("VK-A");
    const b = await ledger.getCase("VK-B");
    expect(a[0]).to.equal(hash("a1"));
    expect(b[0]).to.equal(hash("b1"));
  });

  it("verifyCase returns true only when both root and report hash match", async function () {
    const root = hash("root-x");
    const report = hash("report-x");
    await ledger.registerCase("VK-VERIFY", root, report);

    expect(await ledger.verifyCase("VK-VERIFY", root, report)).to.equal(true);
    // tamper: change the report hash -> verification must fail
    expect(await ledger.verifyCase("VK-VERIFY", root, hash("tampered"))).to.equal(false);
  });

  it("records the registering address per case", async function () {
    await ledger.connect(other).registerCase("VK-WHO", hash("m"), hash("r"));
    const rec = await ledger.getCase("VK-WHO");
    expect(rec[3]).to.equal(other.address);
  });
});
