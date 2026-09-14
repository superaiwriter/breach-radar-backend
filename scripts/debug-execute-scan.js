require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const Scan = require('../src/models/Scan');
const Domain = require('../src/models/Domain');
const { resolveEnabledScanners } = require('../src/scanners');

async function main() {
  await connectDB();
  console.log('DB Connected.');

  const scan = await Scan.findOne({ status: 'In Progress' }).sort({ createdAt: -1 });
  if (!scan) {
    console.log('No In Progress scan found.');
    return;
  }
  console.log('Debugging scan ID:', scan._id);
  console.log('Scan checks:', JSON.stringify(scan.checks, null, 2));

  const domain = await Domain.findById(scan.domainId);
  console.log('Domain:', domain.domain);

  const enabled = resolveEnabledScanners(scan.checks);
  console.log('Enabled scanners list:', enabled);

  const { ADAPTERS } = require('../src/scanners');
  const scanContext = {
    scanId: scan._id,
    workspaceId: scan.workspaceId,
    domainId: scan.domainId,
    authProfileId: scan.authProfileId
  };

  const results = [];
  for (const scannerName of enabled) {
    const adapter = ADAPTERS[scannerName];
    if (!adapter) {
      console.log(`No adapter for scanner: ${scannerName}`);
      continue;
    }

    console.log(`>>> Executing adapter: [${scannerName}]`);
    const start = Date.now();
    try {
      const result = await adapter(domain.domain, null, scanContext);
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      console.log(`<<< Finished adapter: [${scannerName}] in ${duration}s. Success: ${result.success}, Findings: ${result.findings?.length || 0}`);
      results.push(result);
    } catch (error) {
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      console.log(`<<< Failed adapter: [${scannerName}] in ${duration}s. Error: ${error.message}`);
      results.push({
        scanner: scannerName,
        success: false,
        findings: [],
        metadata: { error: error.message }
      });
    }
  }

  console.log('All adapters done.');
}

main()
  .catch(console.error)
  .finally(() => mongoose.connection.close());
