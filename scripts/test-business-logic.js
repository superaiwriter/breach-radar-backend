require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const Domain = require('../src/models/Domain');
const Scan = require('../src/models/Scan');
const Vulnerability = require('../src/models/Vulnerability');
const Workspace = require('../src/models/Workspace');
const { SCAN_STATUS, SCAN_TYPES, DOMAIN_VERIFICATION_STATUS } = require('../src/constants');
const { executeScan } = require('../src/services/scanner.service');

async function main() {
  await connectDB();

  // Find workspace created by seeder
  const workspace = await Workspace.findOne({ name: /Sharma|Super/i });
  if (!workspace) {
    throw new Error('Default workspace not found. Please run dbSeeder first.');
  }

  console.log(`Found workspace: ${workspace.name} (${workspace._id})`);

  const domainName = 'localhost:5000';

  // Upsert domain
  let domain = await Domain.findOne({ workspaceId: workspace._id, domain: domainName });
  if (!domain) {
    domain = new Domain({
      workspaceId: workspace._id,
      domain: domainName,
      status: 'Active',
      statusDetail: 'Configured for local scanning',
      verificationStatus: DOMAIN_VERIFICATION_STATUS.VERIFIED,
      verifiedAt: new Date()
    });
    await domain.save();
    console.log(`Registered local domain ${domainName}`);
  } else {
    domain.status = 'Active';
    domain.verificationStatus = DOMAIN_VERIFICATION_STATUS.VERIFIED;
    await domain.save();
    console.log(`Updated existing local domain ${domainName}`);
  }

  // Clear existing findings for this domain to avoid duplicates in testing
  const deletedCount = await Vulnerability.deleteMany({ domainId: domain._id, category: 'Business Logic' });
  console.log(`Cleared ${deletedCount.deletedCount} old Business Logic vulnerabilities`);

  // Create scan record
  const scan = await Scan.create({
    workspaceId: workspace._id,
    domainId: domain._id,
    scanType: SCAN_TYPES.QUICK,
    status: SCAN_STATUS.QUEUED,
    triggeredBy: 'system-test',
    checks: {
      ssl: false,
      headers: false,
      owasp: true,
      malware: false,
      ports: false,
      compliance: false,
      businessLogic: true
    }
  });

  console.log(`Created test scan ${scan._id} for ${domain.domain}`);

  // Run the scan pipeline
  const result = await executeScan(scan._id);
  
  // Retrieve saved findings
  const savedFindings = await Vulnerability.find({ scanId: scan._id });

  console.log('\n========================================');
  console.log('SCAN COMPLETED');
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
    console.error(`Local business logic test failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.connection.close();
  });
