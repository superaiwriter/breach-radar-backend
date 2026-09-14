const express = require('express');
const router = express.Router();

// GET /api/test-ssti/secure -> Safely sanitizes or escapes template syntax tags
router.get('/secure', (req, res) => {
  const name = req.query.name || '';
  
  // Safe logic: strip out standard template expression tokens
  const cleanName = name.replace(/[{}$%<=]/g, '');
  res.send(`Hello ${cleanName}!`);
});

// GET /api/test-ssti/vulnerable -> Vulnerable to SSTI (evaluates expressions)
router.get('/vulnerable', (req, res) => {
  const name = req.query.name || '';

  // Vulnerable logic: simulates template evaluation for EJS, Handlebars, FreeMarker etc.
  // Check if safe mathematical expressions are passed and evaluate them
  let rendered = name;
  if (name.includes('{{7*7}}')) {
    rendered = name.replace('{{7*7}}', '49');
  } else if (name.includes('${7*7}')) {
    rendered = name.replace('${7*7}', '49');
  } else if (name.includes('<%= 7*7 %>')) {
    rendered = name.replace('<%= 7*7 %>', '49');
  }

  res.send(`Hello ${rendered}!`);
});

// GET /api/test-ssti/reflection -> Simple reflection only
router.get('/reflection', (req, res) => {
  const name = req.query.name || '';
  res.send(`User Dashboard: Hello ${name}!`);
});

// GET /api/test-ssti/fake-200 -> Returns HTTP 200 but generic operational status
router.get('/fake-200', (req, res) => {
  res.status(200).send('<html><body><h1>Template Generation Console</h1><p>Status: OK</p></body></html>');
});

module.exports = router;
