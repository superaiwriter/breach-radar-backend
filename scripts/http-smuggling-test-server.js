const http = require('http');
const fs = require('fs');
const path = require('path');

let smuggledState = {
  clTeSmuggled: false,
  teClSmuggled: false
};

// Create Backend Server
const backend = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const hasCl = req.headers['content-length'] !== undefined;
  const hasTe = req.headers['transfer-encoding'] !== undefined || req.headers['x-transfer-encoding'] !== undefined;

  // 1. Terminate route
  if (url.pathname === '/shutdown') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Shutting down smuggling test server...');
    setTimeout(() => {
      proxy.close();
      backend.close();
      try {
        fs.unlinkSync(portFilePath);
      } catch (e) {}
      process.exit(0);
    }, 100);
    return;
  }

  // 2. /secure -> Rejects request if both CL and TE are present (Secure Parser Agreement)
  if (url.pathname === '/secure') {
    if (hasCl && hasTe) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Bad Request: Incompatible headers (CL and TE)' }));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'secure', message: 'Parser agreed.' }));
  }

  // 3. /fake-200 -> Returns HTTP 200 without smuggling marker or error
  if (url.pathname === '/fake-200') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ message: 'Harmless response' }));
  }

  // 4. /vulnerable-cl-te
  if (url.pathname === '/vulnerable-cl-te') {
    if (hasCl && hasTe) {
      smuggledState.clTeSmuggled = true;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ message: 'First request received CL.TE' }));
    }
    
    if (smuggledState.clTeSmuggled) {
      smuggledState.clTeSmuggled = false;
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('HTTP_SMUGGLING_TEST_MARKER: Smuggled prefix processed (CL.TE)');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ message: 'Normal response' }));
  }

  // 5. /vulnerable-te-cl
  if (url.pathname === '/vulnerable-te-cl') {
    if (hasCl && hasTe) {
      smuggledState.teClSmuggled = true;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ message: 'First request received TE.CL' }));
    }

    if (smuggledState.teClSmuggled) {
      smuggledState.teClSmuggled = false;
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('HTTP_SMUGGLING_TEST_MARKER: Smuggled prefix processed (TE.CL)');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ message: 'Normal response' }));
  }

  res.writeHead(404);
  res.end('Not Found');
});

// Create Proxy Server forwarding requests to the Backend Server
const proxy = http.createServer((req, res) => {
  const backendAddress = backend.address();
  const options = {
    hostname: '127.0.0.1',
    port: backendAddress.port,
    path: req.url,
    method: req.method,
    headers: req.headers
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  req.pipe(proxyReq);

  proxyReq.on('error', (err) => {
    res.writeHead(502);
    res.end('Bad Gateway');
  });
});

// Port persistence filepath
const portFilePath = path.join(__dirname, '../.smuggling-port');

// Bind only to 127.0.0.1 on dynamic ports
backend.listen(0, '127.0.0.1', () => {
  proxy.listen(0, '127.0.0.1', () => {
    const proxyPort = proxy.address().port;
    console.log(`HTTP Request Smuggling test server started.`);
    console.log(`Proxy listening on 127.0.0.1:${proxyPort}`);
    console.log(`Backend listening on 127.0.0.1:${backend.address().port}`);
    
    // Write proxy port to file
    fs.writeFileSync(portFilePath, proxyPort.toString(), 'utf8');
  });
});

// Auto-cleanup on crash/exit
process.on('SIGTERM', () => {
  try {
    fs.unlinkSync(portFilePath);
  } catch (e) {}
  process.exit(0);
});
