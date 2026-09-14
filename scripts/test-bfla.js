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

  // Find workspace created by seeder
  const workspace = await Workspace.findOne({ name: /Sharma/i });
  if (!workspace) {
    throw new Error('Default workspace not found. Please run dbSeeder first.');
  }

  console.log(`Found workspace: ${workspace.name} (${workspace._id})`);

  const domainName = 'localhost:5000';

  // Find local domain
  const domain = await Domain.findOne({ workspaceId: workspace._id, domain: domainName });
  if (!domain) {
    throw new Error('Local domain localhost:5000 not found in database. Make sure seeder completed.');
  }

  // Find User A AuthProfile
  const profileA = await AuthProfile.findOne({
    workspaceId: workspace._id,
    domainId: domain._id,
    username: 'usera@securescan.local'
  });

  if (!profileA) {
    throw new Error('User A AuthProfile not found in database. Make sure seeder completed.');
  }

  console.log(`Found User A AuthProfile: ${profileA.username} (${profileA._id})`);

  // Clear existing BFLA findings for this domain to avoid duplicates in testing
  const deletedCount = await Vulnerability.deleteMany({
    domainId: domain._id,
    category: 'API Security',
    subCategory: 'Broken Function Level Authorization (BFLA)'
  });
  console.log(`Cleared ${deletedCount.deletedCount} old BFLA vulnerabilities`);

  // Create scan record
  const scan = await Scan.create({
    workspaceId: workspace._id,
    domainId: domain._id,
    scanType: SCAN_TYPES.QUICK,
    status: SCAN_STATUS.QUEUED,
    triggeredBy: 'system-test',
    authProfileId: profileA._id, // Assign User A (Normal user) as primary credentials
    checks: {
      ssl: false,
      headers: false,
      owasp: false,
      malware: false,
      ports: false,
      compliance: false,
      businessLogic: false,
      apiSecurity: true
    }
  });

  console.log(`Created test scan ${scan._id} for ${domain.domain}`);

  // Run the scan pipeline
  const result = await executeScan(scan._id);
  
  // Retrieve saved findings
  const savedFindings = await Vulnerability.find({ scanId: scan._id, subCategory: 'Broken Function Level Authorization (BFLA)' });

  console.log('\n========================================');
  console.log('BFLA SCAN COMPLETED');
  console.log('========================================');
  console.log('Scan Status:', result.success ? 'Success' : 'Failed');
  console.log('Findings Found:', savedFindings.length);
  
  savedFindings.forEach((finding, idx) => {
    console.log(`\nFinding #${idx + 1}: ${finding.name}`);
    console.log(`- Severity: ${finding.severity}`);
    console.log(`- Category: ${finding.category}`);
    console.log(`- Subcategory: ${finding.subCategory}`);
    console.log(`- Path: ${finding.path}`);
    console.log(`- Evidence: ${finding.evidence}`);
  });

  console.log('\n========================================');
}

main()
  .catch((error) => {
    console.error(`BFLA test run failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.connection.close();
  });
