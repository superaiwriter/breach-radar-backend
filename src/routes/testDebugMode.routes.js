const express = require('express');
const router = express.Router();

router.get('/vulnerable/trace', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.status(500).send(`
Stack Trace:
ReferenceError: x is not defined
    at Object.<anonymous> (e:\\REACT\\backend\\src\\routes\\testDebugMode.routes.js:6:12)
    at Module._compile (node:internal/modules/cjs/loader:1254:14)
    at Module.load (node:internal/modules/cjs/loader:1119:32)
    at Module._load (node:internal/modules/cjs/loader:960:12)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:81:12)
    at node:internal/main/run_main_module:23:47
  `);
});

router.get('/secure/trace', (req, res) => {
  res.status(500).json({
    success: false,
    error: 'Internal Server Error'
  });
});

module.exports = router;
