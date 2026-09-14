require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const connectDB = require('../src/config/db');
const dbSeeder = require('../src/config/dbSeeder');
const SubscriptionPlan = require('../src/models/SubscriptionPlan');
const User = require('../src/models/User');

let server;

async function runTests() {
  console.log('=== STARTING PRICING & SUPER ADMIN FLOW TEST ===');

  try {
    await connectDB();
    console.log('✔ MongoDB connected.');

    // Run seeder
    await dbSeeder();
    console.log('✔ dbSeeder executed.');

    // Start ephemeral server
    const port = 5999;
    server = app.listen(port);
    console.log(`✔ Test server listening on port ${port}`);

    const baseUrl = `http://127.0.0.1:${port}/api/v1`;

    // 1. Test Public Pricing API
    console.log('\n--- 1. Testing Public Pricing API ---');
    const publicRes = await fetch(`${baseUrl}/pricing`);
    if (publicRes.status !== 200) {
      throw new Error(`Public pricing API returned status ${publicRes.status}`);
    }
    const publicData = await publicRes.json();
    console.log(`✔ Public pricing API status: 200 OK. Count of active plans: ${publicData.count}`);
    console.log('Plans returned:', publicData.plans.map(p => ({
      name: p.name,
      price: p.price,
      currency: p.currency,
      popular: p.popular,
      featuresCount: p.features.length,
      cta: p.cta
    })));

    if (!publicData.plans || publicData.plans.length === 0) {
      throw new Error('Public pricing API returned no plans.');
    }

    // Verify all 4 default plans are returned
    const planNames = publicData.plans.map(p => p.name);
    for (const expected of ['Free', 'Starter', 'Professional', 'Enterprise']) {
      if (!planNames.includes(expected)) {
        throw new Error(`Expected plan ${expected} missing from public pricing output!`);
      }
    }
    console.log('✔ All standard plans (Free, Starter, Professional, Enterprise) verified in Public API.');

    // 2. Test Super Admin API Auth Protection
    console.log('\n--- 2. Testing Super Admin Auth Protection ---');
    const unauthRes = await fetch(`${baseUrl}/super-admin/subscriptions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'HackerPlan', price: 0, domainLimit: 1, scanLimit: 1 })
    });
    console.log(`✔ Unauthenticated plan creation blocked with status: ${unauthRes.status} (Expected 401)`);
    if (unauthRes.status !== 401) {
      throw new Error(`Expected status 401 for unauthenticated request, got ${unauthRes.status}`);
    }

    // Find or create Super Admin User and generate JWT
    let superAdmin = await User.findOne({ role: 'super_admin' });
    if (!superAdmin) {
      throw new Error('Super Admin user not found in DB.');
    }

    const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_access_key_12345!';
    const adminToken = jwt.sign(
      { userId: superAdmin._id, email: superAdmin.email, role: 'super_admin' },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 3. Test Super Admin Plan Management
    console.log('\n--- 3. Testing Super Admin Plan Creation & Modification ---');
    const testPlanPayload = {
      name: 'UltraCustomPlan_' + Date.now(),
      displayName: 'Ultra Custom Tier',
      description: 'Dynamic plan created by Super Admin for high performance',
      price: 4999,
      currency: 'INR',
      billingInterval: 'month',
      domainLimit: 50,
      scanLimit: 500,
      seatLimit: 20,
      sortOrder: 10,
      isActive: true,
      isPopular: true,
      ctaText: 'Get Ultra Power',
      features: ['50 Verified Domains', '500 Scans / month', 'Dedicated GPU scanners', '24/7 Phone Support']
    };

    const createRes = await fetch(`${baseUrl}/super-admin/subscriptions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify(testPlanPayload)
    });

    const createData = await createRes.json();
    console.log(`✔ Plan creation status: ${createRes.status}. Response message: ${createData.message}`);
    if (createRes.status !== 201 || !createData.plan) {
      throw new Error(`Failed to create plan: ${JSON.stringify(createData)}`);
    }

    const createdPlanId = createData.plan._id;

    // 4. Verify new plan immediately reflects in Public Pricing API
    console.log('\n--- 4. Verifying Real-Time Reflection on Public Pricing API ---');
    const publicAfterCreate = await (await fetch(`${baseUrl}/pricing`)).json();
    const foundCreated = publicAfterCreate.plans.find(p => p.name === testPlanPayload.name);
    if (!foundCreated) {
      throw new Error('Newly created plan did not appear on public pricing API!');
    }
    console.log(`✔ Found new plan on Public API: ${foundCreated.name}, Price: ₹${foundCreated.price}, CTA: ${foundCreated.cta}`);

    // 5. Update Plan Price & Features via Super Admin API
    console.log('\n--- 5. Testing Plan Update by Super Admin ---');
    const updateRes = await fetch(`${baseUrl}/super-admin/subscriptions/${createdPlanId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        price: 5999,
        description: 'Updated dynamic description by Super Admin',
        features: ['50 Verified Domains', '500 Scans / month', 'Dedicated GPU scanners', '24/7 Phone Support', 'Custom SLA 99.99%']
      })
    });
    const updateData = await updateRes.json();
    console.log(`✔ Plan update status: ${updateRes.status}. Updated Price: ${updateData.plan?.price}`);

    // 6. Verify Public API reflects updated price & features
    const publicAfterUpdate = await (await fetch(`${baseUrl}/pricing`)).json();
    const foundUpdated = publicAfterUpdate.plans.find(p => p.name === testPlanPayload.name);
    if (!foundUpdated || foundUpdated.price !== '5,999' || !foundUpdated.features.includes('Custom SLA 99.99%')) {
      throw new Error(`Updated plan details not reflected in public API! Got: ${JSON.stringify(foundUpdated)}`);
    }
    console.log('✔ Public API accurately reflects the updated price (₹5,999) and new feature item.');

    // 7. Test Deactivation (Hide from Landing Page)
    console.log('\n--- 7. Testing Plan Deactivation & Public Visibility ---');
    const toggleRes = await fetch(`${baseUrl}/super-admin/subscriptions/${createdPlanId}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ isActive: false })
    });
    const toggleData = await toggleRes.json();
    console.log(`✔ Deactivation status: ${toggleRes.status}. Plan active: ${toggleData.plan?.isActive}`);

    // Check that public API no longer lists the deactivated plan
    const publicAfterDeactivate = await (await fetch(`${baseUrl}/pricing`)).json();
    const foundDeactivated = publicAfterDeactivate.plans.find(p => p.name === testPlanPayload.name);
    if (foundDeactivated) {
      throw new Error('Deactivated plan should NOT appear on public pricing API, but was returned!');
    }
    console.log('✔ Deactivated plan is properly hidden from Public Pricing API.');

    // 8. Delete test plan and cleanup
    console.log('\n--- 8. Cleaning up test plan ---');
    const deleteRes = await fetch(`${baseUrl}/super-admin/subscriptions/${createdPlanId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });
    console.log(`✔ Plan deletion status: ${deleteRes.status}`);

    console.log('\n=============================================');
    console.log('✔ ALL PRICING & SUPER ADMIN FLOW TESTS PASSED!');
    console.log('=============================================');
  } catch (error) {
    console.error('❌ Test failed with error:', error);
    process.exitCode = 1;
  } finally {
    if (server) {
      server.close();
    }
    await mongoose.disconnect();
    process.exit();
  }
}

runTests();
