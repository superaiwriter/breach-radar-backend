const express = require('express');
const router = express.Router();

// Mock database results
const products = [
  { id: 1, name: 'Secure Database Shield', category: 'Security', price: 299.99 },
  { id: 2, name: 'Network Intrusion Detector', category: 'Infrastructure', price: 499.99 }
];

// GET /api/test-sqli/secure -> Safely parameterized/handled query
router.get('/secure', (req, res) => {
  const search = req.query.q || '';
  
  // Safe handling: stripping SQL special characters
  const cleanSearch = search.replace(/['"\\#\-\-]/g, '').toLowerCase();

  const filtered = products.filter(p => 
    p.name.toLowerCase().includes(cleanSearch) || 
    p.category.toLowerCase().includes(cleanSearch)
  );

  res.json({
    success: true,
    results: filtered
  });
});

// GET /api/test-sqli/vulnerable-error -> Returns DB syntax error if quotes are present
router.get('/vulnerable-error', (req, res) => {
  const search = req.query.q || '';

  // Vulnerable logic: check if SQL syntax characters exist to simulate MySQL syntax error
  if (search.includes("'") || search.includes('"') || search.includes('`')) {
    return res.status(500).json({
      success: false,
      message: 'Database query execution failed',
      error: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '\"' at line 1"
    });
  }

  const filtered = products.filter(p => 
    p.name.toLowerCase().includes(search.toLowerCase())
  );

  res.json({
    success: true,
    results: filtered
  });
});

// GET /api/test-sqli/vulnerable-boolean -> Simulates boolean-based logic differences
router.get('/vulnerable-boolean', (req, res) => {
  const idParam = req.query.id || '';

  // True condition check: e.g. "1" or "1' AND '1'='1"
  // False condition check: e.g. "1' AND '1'='2"
  if (!idParam) {
    return res.status(400).json({ success: false, error: 'ID parameter missing' });
  }

  // Detect simulated boolean conditions
  let isTrue = true;
  if (idParam.includes("' AND '1'='2") || idParam.includes("' AND '1'='0") || idParam.includes(' AND 1=2')) {
    isTrue = false;
  }

  if (isTrue) {
    res.json({
      success: true,
      results: [products[0]]
    });
  } else {
    res.json({
      success: true,
      results: []
    });
  }
});

// GET /api/test-sqli/fake-200 -> Always returns HTTP 200 with normal output
router.get('/fake-200', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'Operational',
    message: 'Operational baseline status. No search criteria provided.'
  });
});

module.exports = router;
