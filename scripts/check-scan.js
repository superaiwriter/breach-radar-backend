require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const Scan = require('../src/models/Scan');
const Domain = require('../src/models/Domain');

async function main() {
  await connectDB();
  const scan = await Scan.findOne().sort({ createdAt: -1 });
  console.log('Latest scan record:', {
    id: scan?._id,
    status: scan?.status,
    createdAt: scan?.createdAt,
    startedAt: scan?.startedAt,
    completedAt: scan?.completedAt,
    vulnerabilitiesCount: scan?.vulnerabilitiesCount,
    errorDetail: scan?.errorDetail
  });

  if (scan) {
    const domain = await Domain.findById(scan.domainId);
    console.log('Domain status detail:', domain?.statusDetail);
  }
}

main()
  .catch(console.error)
  .finally(() => mongoose.connection.close());
