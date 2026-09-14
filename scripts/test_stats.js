const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const connectDB = require('../src/config/db');
const statsController = require('../src/controllers/stats.controller');

async function runTest() {
  try {
    await connectDB();
    console.log("Connected to DB successfully.");

    const req = {};
    const res = {
      status: function(code) {
        console.log("Response Code:", code);
        return this;
      },
      json: function(data) {
        console.log("Response Data:", JSON.stringify(data, null, 2));
        process.exit(0);
      }
    };
    const next = function(err) {
      console.error("Error in controller:", err);
      process.exit(1);
    };

    await statsController.getPlatformStats(req, res, next);
  } catch (error) {
    console.error("Test execution failed:", error);
    process.exit(1);
  }
}

runTest();
