require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const { scanCloudInfrastructure } = require('../src/scanners/cloudInfrastructure.scanner');

// Enable default credentials testing
process.env.DEFAULT_CREDENTIALS_TEST = 'true';

async function main() {
  await connectDB();

  console.log('--- TEST 1: Scanning a Local Target ---');
  const localResult = await scanCloudInfrastructure('localhost:5000');
  console.log('Local Scan Success:', localResult.success);
  console.log('Local Scan Checks Performed:', localResult.metadata.checksPerformed.filter(c => c.startsWith('DefaultCreds')));
  
  const hasLocalMocks = localResult.metadata.checksPerformed.some(c => c.includes('test-default-creds'));
  console.log('Local scan tested mock endpoints:', hasLocalMocks ? 'YES (Correct)' : 'NO (Incorrect)');

  console.log('\n--- TEST 2: Scanning a Non-Local Target (Mocked as localhost.attacker.com) ---');
  // We use a domain that is non-local. It will fail network requests, but we verify if it tries to test mock endpoints.
  const remoteResult = await scanCloudInfrastructure('localhost.attacker.com');
  console.log('Remote Scan Success:', remoteResult.success);
  console.log('Remote Scan Checks Performed:', remoteResult.metadata.checksPerformed.filter(c => c.startsWith('DefaultCreds')));

  const hasRemoteMocks = remoteResult.metadata.checksPerformed.some(c => c.includes('test-default-creds'));
  console.log('Remote scan tested mock endpoints:', hasRemoteMocks ? 'YES (Incorrect)' : 'NO (Correct)');

  if (hasLocalMocks && !hasRemoteMocks) {
    console.log('\n>>> SUCCESS: Mock endpoints are isolated to local targets! <<<');
  } else {
    console.log('\n>>> FAILURE: Isolation check failed! <<<');
  }
}

main()
  .catch((error) => {
    console.error(`Verification failed: ${error.stack}`);
  })
  .finally(async () => {
    await mongoose.connection.close();
  });
