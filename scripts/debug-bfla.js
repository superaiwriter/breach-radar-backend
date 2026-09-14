require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const Domain = require('../src/models/Domain');
const Workspace = require('../src/models/Workspace');
const AuthProfile = require('../src/models/AuthProfile');
const authProfileService = require('../src/services/authProfile.service');
const authSessionService = require('../src/services/authSession.service');
const http = require('http');

function makeRequest(urlString, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const req = http.request(url, { method: 'GET', headers }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve({ statusCode: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function main() {
  await connectDB();

  const workspace = await Workspace.findOne({ name: /Sharma/i });
  const domain = await Domain.findOne({ workspaceId: workspace._id, domain: 'localhost:5000' });
  const profileA = await AuthProfile.findOne({ workspaceId: workspace._id, domainId: domain._id, username: 'usera@securescan.local' });
  const profileAdmin = await AuthProfile.findOne({ workspaceId: workspace._id, domainId: domain._id, username: 'admin@securescan.local' });

  const decryptedA = await authProfileService.resolveDecryptedProfile(workspace._id, profileA._id);
  const contextA = await authSessionService.resolveAuthContext(domain.domain, decryptedA);

  const decryptedAdmin = await authProfileService.resolveDecryptedProfile(workspace._id, profileAdmin._id);
  const contextAdmin = await authSessionService.resolveAuthContext(domain.domain, decryptedAdmin);

  const getHeaders = (ctx) => {
    const hdrs = {};
    if (ctx.headers) Object.assign(hdrs, ctx.headers);
    if (ctx.cookieJar) hdrs['Cookie'] = ctx.cookieJar;
    return hdrs;
  };

  const urlVulnerable = 'http://localhost:5000/api/v1/test-bfla/vulnerable/admin/users';
  const urlSecure = 'http://localhost:5000/api/v1/test-bfla/secure/admin/users';

  console.log('--- VULNERABLE ADMIN PATH ---');
  const resAdminV = await makeRequest(urlVulnerable, getHeaders(contextAdmin));
  console.log('Admin Access Status:', resAdminV.statusCode, 'Body:', resAdminV.body);

  const resUserV = await makeRequest(urlVulnerable, getHeaders(contextA));
  console.log('User A Access Status:', resUserV.statusCode, 'Body:', resUserV.body);

  console.log('\n--- SECURE ADMIN PATH ---');
  const resAdminS = await makeRequest(urlSecure, getHeaders(contextAdmin));
  console.log('Admin Access Status:', resAdminS.statusCode, 'Body:', resAdminS.body);

  const resUserS = await makeRequest(urlSecure, getHeaders(contextA));
  console.log('User A Access Status:', resUserS.statusCode, 'Body:', resUserS.body);
}

main().catch(console.error).finally(() => mongoose.connection.close());
