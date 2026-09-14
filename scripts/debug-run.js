require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const { runScanners } = require('../src/scanners');
const { resolveEnabledScanners } = require('../src/scanners');

async function main() {
  console.log('Connecting to MongoDB...');
  await connectDB();
  console.log('MongoDB connected successfully!');

  const domain = 'www.netflix.com';
  const checks = {
    ssl: true,
    headers: true,
    owasp: false,
    malware: false,
    ports: false,
    compliance: false
  };

  const enabled = resolveEnabledScanners(checks);
  console.log('Enabled scanners for these checks:', enabled);

  const { ADAPTERS } = require('../src/scanners');

  for (const scannerName of enabled) {
    const adapter = ADAPTERS[scannerName];
    if (!adapter) {
      console.log(`No adapter found for ${scannerName}`);
      continue;
    }

    console.log(`>>> Starting scanner: [${scannerName}]`);
    const start = Date.now();
    try {
      const result = await adapter(domain, null, { domainId: new mongoose.Types.ObjectId() });
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      console.log(`<<< Finished scanner: [${scannerName}] in ${duration}s. Success: ${result.success}, Findings: ${result.findings?.length || 0}`);
    } catch (err) {
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      console.log(`<<< Failed scanner: [${scannerName}] in ${duration}s. Error: ${err.message}`);
    }
  }

  console.log('All scanners completed.');
}

main()
  .catch((err) => {
    console.error('Debug script failed:', err);
  })
  .finally(async () => {
    await mongoose.connection.close();
    console.log('MongoDB connection closed.');
  });
