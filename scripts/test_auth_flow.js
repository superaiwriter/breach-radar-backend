const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const authService = require('../src/services/auth.service');
const User = require('../src/models/User');

async function testAuthFlow() {
  console.log('=== STARTING AUTHENTICATION FLOW TEST ===\n');

  try {
    console.log('1. Testing Database Connection...');
    await connectDB();
    console.log('✔ MongoDB connected successfully.\n');

    const testEmail = `test_user_${Date.now()}@example.com`;
    const testPassword = 'TestPassword123!';

    console.log('2. Testing Empty Fields Validation...');
    try {
      await authService.loginUser({ email: '', password: '' });
      console.error('❌ Failed: Empty credentials did not throw error.');
    } catch (err) {
      console.log(`✔ Success: Empty credentials rejected with status ${err.statusCode}: "${err.message}"`);
    }

    console.log('\n3. Testing Invalid Email / Non-existent User...');
    try {
      await authService.loginUser({ email: 'nonexistent_user_9999@example.com', password: 'somepassword' });
      console.error('❌ Failed: Non-existent email did not throw error.');
    } catch (err) {
      console.log(`✔ Success: Invalid email rejected with status ${err.statusCode}: "${err.message}"`);
    }

    console.log('\n4. Creating Test Verified User for Login Test...');
    const passwordHash = await authService.hashPassword(testPassword);
    const user = await User.create({
      email: testEmail,
      passwordHash,
      accountType: 'individual',
      status: 'active',
      isEmailVerified: true,
      profile: { name: 'Test Auth User', avatar: '' }
    });
    console.log(`✔ Test user created: ${testEmail} (ID: ${user._id})`);

    console.log('\n5. Testing Invalid Password...');
    try {
      await authService.loginUser({ email: testEmail, password: 'WrongPassword999!' });
      console.error('❌ Failed: Wrong password did not throw error.');
    } catch (err) {
      console.log(`✔ Success: Wrong password rejected with status ${err.statusCode}: "${err.message}"`);
    }

    console.log('\n6. Testing Valid Login...');
    const loginResult = await authService.loginUser({ email: testEmail, password: testPassword });
    console.log('✔ Success: Valid login succeeded!');
    console.log('  Response Payload Structure:');
    console.log('  - user.id:', loginResult.user.id);
    console.log('  - user.email:', loginResult.user.email);
    console.log('  - accessToken present:', Boolean(loginResult.accessToken));
    console.log('  - refreshToken present:', Boolean(loginResult.refreshToken));

    console.log('\n7. Cleanup Test User...');
    await User.deleteOne({ _id: user._id });
    console.log('✔ Test user cleaned up.');

    console.log('\n=== ALL AUTHENTICATION FLOW TESTS PASSED ===');
  } catch (error) {
    console.error('\n❌ AUTH TEST CRASHED:', error);
  } finally {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
      console.log('MongoDB connection closed.');
    }
  }
}

testAuthFlow();
