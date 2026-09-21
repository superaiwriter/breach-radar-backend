const mongoose = require('mongoose');
const dns = require('dns');
const logger = require('./logger');

// Set bufferCommands to false globally so Mongoose operations fail fast instead of hanging indefinitely if DB is disconnected
mongoose.set('bufferCommands', false);

// Attach connection lifecycle event listeners for production diagnostics
mongoose.connection.on('error', (err) => {
  logger.error(`[database] Mongoose connection error event: name=${err.name}, message=${err.message}`);
});

mongoose.connection.on('disconnected', () => {
  logger.warn('[database] Mongoose disconnected from MongoDB cluster.');
});

mongoose.connection.on('reconnected', () => {
  logger.info('[database] Mongoose reconnected to MongoDB cluster.');
});

// Configure custom DNS servers if explicitly requested or if Google Cloud Run SRV resolution needs fallback
if (process.env.CUSTOM_DNS_SERVERS) {
  try {
    dns.setServers(process.env.CUSTOM_DNS_SERVERS.split(',').map((s) => s.trim()));
    logger.info(`[database] Custom DNS servers configured: ${process.env.CUSTOM_DNS_SERVERS}`);
  } catch (dnsErr) {
    logger.warn(`[database] Failed to set custom DNS servers: ${dnsErr.message}`);
  }
}

const getMongoUri = () => {
  const uri = process.env.MONGODB_URI || process.env.MONGO_URI;
  if (!uri) return null;
  return String(uri).trim();
};

const connectDB = async () => {
  const rawUri = getMongoUri();
  const hasUri = Boolean(rawUri);
  const isProduction = process.env.NODE_ENV === 'production';

  logger.info(`[database] Connection attempt started - state=${mongoose.connection.readyState}, envPresent=${hasUri}, isProd=${isProduction}`);

  if (isProduction && (!rawUri || rawUri.includes('localhost') || rawUri.includes('127.0.0.1'))) {
    const errorMsg = '[database] Localhost MongoDB or fallback URI configured in production environment. A valid remote MongoDB Atlas connection string (MONGODB_URI or MONGO_URI) is required.';
    logger.error(errorMsg);
    const err = new Error(errorMsg);
    err.statusCode = 500;
    throw err;
  }

  const connUri = rawUri || 'mongodb://127.0.0.1:27017/cybersecurity_scanner';

  try {
    const conn = await mongoose.connect(connUri, {
      autoIndex: !isProduction, // Build indexes in dev, skip in production
      serverSelectionTimeoutMS: 5000, // 5s timeout for server selection (fast failure)
      connectTimeoutMS: 5000,         // 5s initial TCP connection timeout
      socketTimeoutMS: 45000,         // 45s socket idle timeout
      family: 4,                      // Prefer IPv4 for Cloud Run compatibility
    });

    logger.info(`[database] Connection succeeded: host=${conn.connection.host}, db=${conn.connection.name}`);
    return conn;
  } catch (error) {
    logger.error(`[database] Connection failed: name=${error.name}, code=${error.code || 'N/A'}, message=${error.message}`);
    if (error.stack) {
      logger.error(`[database] Stack trace:\n${error.stack}`);
    }
    throw error;
  }
};

let isConnecting = false;

const ensureDBConnected = async () => {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }
  if (isConnecting) {
    let waits = 0;
    while (isConnecting && waits < 10) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      waits++;
    }
    if (mongoose.connection.readyState === 1) return mongoose.connection;
  }

  isConnecting = true;
  try {
    return await connectDB();
  } finally {
    isConnecting = false;
  }
};

module.exports = connectDB;
module.exports.connectDB = connectDB;
module.exports.ensureDBConnected = ensureDBConnected;
module.exports.getMongoUri = getMongoUri;



