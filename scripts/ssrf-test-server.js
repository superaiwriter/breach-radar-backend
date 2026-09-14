const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT_FILE = path.join(__dirname, '..', '.ssrf-port');

class SsrfTestServer {
  constructor() {
    this.server = null;
    this.port = null;
    this.hits = [];
  }

  start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        // Parse URL
        const parsedUrl = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
        const pathname = parsedUrl.pathname;

        if (pathname === '/ssrf-marker') {
          this.hits.push({
            timestamp: new Date().toISOString(),
            method: req.method,
            headers: req.headers,
            url: req.url
          });
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('SSRF_TEST_MARKER');
        } else if (pathname === '/ssrf-hits') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(this.hits));
        } else if (pathname === '/ssrf-reset') {
          this.hits = [];
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('OK');
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
        }
      });

      // Bind only to 127.0.0.1 and use port 0 for dynamic allocation
      this.server.listen(0, '127.0.0.1', (err) => {
        if (err) {
          return reject(err);
        }
        this.port = this.server.address().port;
        // Write the port to .ssrf-port file so that external scanner processes can discover it
        try {
          fs.writeFileSync(PORT_FILE, String(this.port), 'utf8');
        } catch (fileErr) {
          console.error(`Warning: could not write .ssrf-port file: ${fileErr.message}`);
        }
        resolve(this.port);
      });
    });
  }

  stop() {
    return new Promise((resolve) => {
      // Clean up port file
      try {
        if (fs.existsSync(PORT_FILE)) {
          fs.unlinkSync(PORT_FILE);
        }
      } catch (fileErr) {
        // ignore
      }

      if (this.server) {
        this.server.close(() => {
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

// Support running directly from CLI
if (require.main === module) {
  const serverInstance = new SsrfTestServer();
  serverInstance.start()
    .then((port) => {
      console.log(`SSRF test callback server listening on 127.0.0.1:${port}`);
      // Handle shutdown signals
      const cleanup = () => {
        serverInstance.stop().then(() => {
          process.exit(0);
        });
      };
      process.on('SIGINT', cleanup);
      process.on('SIGTERM', cleanup);
    })
    .catch((err) => {
      console.error(`Failed to start SSRF test server: ${err.message}`);
      process.exit(1);
    });
}

module.exports = SsrfTestServer;
