require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const Domain = require('../src/models/Domain');
const Scan = require('../src/models/Scan');
const Vulnerability = require('../src/models/Vulnerability');
const Workspace = require('../src/models/Workspace');
const AuthProfile = require('../src/models/AuthProfile');
const { SCAN_STATUS, SCAN_TYPES } = require('../src/constants');
const { executeScan } = require('../src/services/scanner.service');

async function main() {
  await connectDB();

  const workspace = await Workspace.findOne({ name: /Sharma/i });
  if (!workspace) {
    throw new Error('Default workspace not found. Please run dbSeeder first.');
  }

  const domainName = 'localhost:5000';
  const domain = await Domain.findOne({ workspaceId: workspace._id, domain: domainName });
  if (!domain) {
    throw new Error('Local domain localhost:5000 not found in database. Make sure seeder completed.');
  }

  const profileA = await AuthProfile.findOne({
    workspaceId: workspace._id,
    domainId: domain._id,
    username: 'usera@securescan.local'
  });
  if (!profileA) {
    throw new Error('User A AuthProfile not found. Make sure seeder completed.');
  }

  // Clear old findings
  const deletedCount = await Vulnerability.deleteMany({
    domainId: domain._id,
    category: 'Cloud & Infrastructure',
    subCategory: 'Git Repository Exposure'
  });
  console.log(`Cleared ${deletedCount.deletedCount} old Git Repository Exposure findings`);

  // Create scan
  const scan = await Scan.create({
    workspaceId: workspace._id,
    domainId: domain._id,
    scanType: SCAN_TYPES.QUICK,
    status: SCAN_STATUS.QUEUED,
    triggeredBy: 'system-test',
    authProfileId: profileA._id,
    checks: {
      ssl: false,
      headers: false,
      owasp: false,
      malware: false,
      ports: false,
      compliance: false,
      businessLogic: false,
      apiSecurity: false,
      cloudInfrastructure: false,
      fileUpload: false,
      injection: false,
      clientSide: false,
      ssrf: false,
      hostHeaderInjection: false,
      httpRequestSmuggling: false,
      gitRepositoryExposure: true
    }
  });

  console.log(`Created test scan ${scan._id}`);
  const result = await executeScan(scan._id);

  // Retrieve findings
  const findings = await Vulnerability.find({
    scanId: scan._id,
    subCategory: 'Git Repository Exposure'
  });

  console.log('\n========================================');
  console.log('GIT REPOSITORY EXPOSURE SCAN COMPLETED');
  console.log('========================================');
  console.log('Scan Status:', result.success ? 'Success' : 'Failed');
  console.log('Findings Found:', findings.length);

  findings.forEach((finding, idx) => {
    console.log(`\nFinding #${idx + 1}: ${finding.name}`);
    console.log(`- Severity: ${finding.severity}`);
    console.log(`- Path: ${finding.path}`);
    console.log(`- Evidence: ${finding.evidence}`);
  });

  // Verify positive case
  const hasVuln = findings.some(f => f.path === '/api/test-git-exposure/vulnerable/.git/');
  if (!hasVuln) {
    throw new Error('Test failed: Git repository exposure was not detected.');
  }
  console.log('\nPositive Case Check: PASSED');

  // Verify negative case
  const hasSecure = findings.some(f => f.path === '/api/test-git-exposure/secure/.git/');
  if (hasSecure) {
    throw new Error('Test failed: false positive generated for secure Git repository.');
  }
  console.log('Negative Case Check: PASSED');

  // Test duplicate prevention
  const duplicateScan = await Scan.create({
    workspaceId: workspace._id,
    domainId: domain._id,
    scanType: SCAN_TYPES.QUICK,
    status: SCAN_STATUS.QUEUED,
    triggeredBy: 'system-test',
    authProfileId: profileA._id,
    checks: { gitRepositoryExposure: true }
  });

  console.log(`\nRunning duplicate scan ${duplicateScan._id}...`);
  await executeScan(duplicateScan._id);

  const totalOpenInDb = await Vulnerability.countDocuments({
    domainId: domain._id,
    subCategory: 'Git Repository Exposure',
    status: { $ne: 'Resolved' }
  });

  console.log(`Total open findings in DB: ${totalOpenInDb}`);
  if (totalOpenInDb !== 1) {
    throw new Error(`Deduplication failed: expected 1 open finding, found ${totalOpenInDb}`);
  }
  console.log('Duplicate Prevention Check: PASSED');

  console.log('\n========================================');
  console.log('ALL GIT REPOSITORY EXPOSURE TEST VERIFICATIONS PASSED SUCCESSFULLY!');
  console.log('========================================');
}

main()
  .catch((error) => {
    console.error(`\nGit Repository Exposure tests failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.connection.close();
  });
