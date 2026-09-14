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

// Enable default credentials testing inside test environment explicitly
process.env.DEFAULT_CREDENTIALS_TEST = 'true';

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

  // Find User A AuthProfile to assign as primary
  const profileA = await AuthProfile.findOne({
    workspaceId: workspace._id,
    domainId: domain._id,
    username: 'usera@securescan.local'
  });

  if (!profileA) {
    throw new Error('User A AuthProfile not found. Make sure seeder completed.');
  }

  // Clear existing Default Credentials findings for this domain to avoid duplicates in testing
  const deletedCount = await Vulnerability.deleteMany({
    domainId: domain._id,
    category: 'Cloud & Infrastructure',
    subCategory: 'Default Credentials'
  });
  console.log(`Cleared ${deletedCount.deletedCount} old Default Credentials vulnerabilities`);

  // Create scan record
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
      cloudInfrastructure: true
    }
  });

  console.log(`Created test scan ${scan._id} for ${domain.domain}`);

  // Run the scan pipeline
  const result = await executeScan(scan._id);
  
  // Retrieve saved findings
  const savedFindings = await Vulnerability.find({ scanId: scan._id, subCategory: 'Default Credentials' });

  console.log('\n========================================');
  console.log('DEFAULT CREDENTIALS SCAN COMPLETED');
  console.log('========================================');
  console.log('Scan Status:', result.success ? 'Success' : 'Failed');
  console.log('Findings Found:', savedFindings.length);
  
  savedFindings.forEach((finding, idx) => {
    console.log(`\nFinding #${idx + 1}: ${finding.name}`);
    console.log(`- Severity: ${finding.severity}`);
    console.log(`- Category: ${finding.category}`);
    console.log(`- Subcategory: ${finding.subCategory}`);
    console.log(`- Path: ${finding.path}`);
    console.log(`- Evidence:\n${finding.evidence}`);
  });

  console.log('\n========================================');
}

main()
  .catch((error) => {
    console.error(`Default Credentials test run failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.connection.close();
  });
