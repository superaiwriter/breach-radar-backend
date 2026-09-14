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

  // Find User A AuthProfile to assign as primary
  const profileA = await AuthProfile.findOne({
    workspaceId: workspace._id,
    domainId: domain._id,
    username: 'usera@securescan.local'
  });

  if (!profileA) {
    throw new Error('User A AuthProfile not found. Make sure seeder completed.');
  }

  // Clear existing Sensitive Information Disclosure findings for this domain to avoid duplicates in testing
  const deletedCount = await Vulnerability.deleteMany({
    domainId: domain._id,
    category: 'Cloud & Infrastructure',
    subCategory: 'Sensitive Information Disclosure'
  });
  console.log(`Cleared ${deletedCount.deletedCount} old Sensitive Information Disclosure vulnerabilities`);

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
  const savedFindings = await Vulnerability.find({ scanId: scan._id, subCategory: 'Sensitive Information Disclosure' });

  console.log('\n========================================');
  console.log('SENSITIVE INFORMATION DISCLOSURE SCAN COMPLETED');
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

  // Verify correctness programmatically
  let hasApiKeyFinding = false;
  let hasDbStringFinding = false;
  let hasSecureOrHarmlessFinding = false;
  let secretsLeaked = false;

  savedFindings.forEach((finding) => {
    if (finding.path === '/api/v1/test-sensitive-disclosure/vulnerable/apikey') {
      hasApiKeyFinding = true;
    }
    if (finding.path === '/api/v1/test-sensitive-disclosure/vulnerable/dbstring') {
      hasDbStringFinding = true;
    }
    if (
      finding.path === '/api/v1/test-sensitive-disclosure/secure/safe' ||
      finding.path === '/api/v1/test-sensitive-disclosure/secure/harmless'
    ) {
      hasSecureOrHarmlessFinding = true;
    }

    // Check evidence for leaks
    const ev = finding.evidence;
    if (
      ev.includes('AIzaSyA1') ||
      ev.includes('AKIAIOS') ||
      ev.includes('wJalrXUtn') ||
      ev.includes('MySecretPassword123')
    ) {
      secretsLeaked = true;
    }
  });

  console.log('\n--- VERIFICATION CHECKLIST ---');
  console.log(`Vulnerable API key endpoint detected: ${hasApiKeyFinding ? 'PASSED' : 'FAILED'}`);
  console.log(`Vulnerable DB string endpoint detected: ${hasDbStringFinding ? 'PASSED' : 'FAILED'}`);
  console.log(`Secure/harmless endpoints generated no findings: ${!hasSecureOrHarmlessFinding ? 'PASSED' : 'FAILED'}`);
  console.log(`Secret values redacted in evidence: ${!secretsLeaked ? 'PASSED' : 'FAILED'}`);
  
  const allPassed = hasApiKeyFinding && hasDbStringFinding && !hasSecureOrHarmlessFinding && !secretsLeaked;
  console.log(`Overall Test Status: ${allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
  console.log('========================================');
  
  if (!allPassed) {
    process.exitCode = 1;
  }
}

main()
  .catch((error) => {
    console.error(`Sensitive Information Disclosure test run failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.connection.close();
  });
