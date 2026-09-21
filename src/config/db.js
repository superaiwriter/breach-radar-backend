const mongoose = require('mongoose');
const logger = require('./logger');

// Set bufferCommands to false globally so Mongoose operations fail fast instead of hanging indefinitely if DB is disconnected
mongoose.set('bufferCommands', false);

// Attach connection lifecycle event listeners for production diagnostics
mongoose.connection.on('error', (err) => {
  logger.error(`[database] Mongoose connection error: ${err.message}`);
});

mongoose.connection.on('disconnected', () => {
  logger.warn('[database] Mongoose disconnected from MongoDB cluster.');
});

mongoose.connection.on('reconnected', () => {
  logger.info('[database] Mongoose reconnected to MongoDB cluster.');
});

// Set fallback DNS servers only if custom DNS is explicitly requested
if (process.env.CUSTOM_DNS_SERVERS) {
  try {
    const dns = require('dns');
    dns.setServers(process.env.CUSTOM_DNS_SERVERS.split(',').map((s) => s.trim()));
  } catch (dnsErr) {
    logger.warn(`[database] Failed to set custom DNS servers: ${dnsErr.message}`);
  }
}

const connectDB = async () => {
  try {
    const connUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/cybersecurity_scanner';
    
    const isProduction = process.env.NODE_ENV === 'production';
    if (isProduction && (!process.env.MONGODB_URI || connUri.includes('localhost') || connUri.includes('127.0.0.1'))) {
      const errorMsg = '[database] Localhost MongoDB or fallback URI is configured, but environment is production. A remote MongoDB Atlas cluster connection string (MONGODB_URI) is required.';
      logger.error(errorMsg);
      throw new Error(errorMsg);
    }

    logger.info('[database] Connecting to MongoDB cluster...');
    
    const conn = await mongoose.connect(connUri, {
      autoIndex: !isProduction, // Build indexes in dev. Turn off in heavy prod.
      serverSelectionTimeoutMS: 5000, // 5s timeout for server selection (fast failure)
      connectTimeoutMS: 5000,         // 5s initial TCP connection timeout
      socketTimeoutMS: 45000,         // 45s socket idle timeout
    });

    logger.info(`[database] MongoDB Connected: host=${conn.connection.host}, db=${conn.connection.name}`);
    return conn;
  } catch (error) {
    logger.error(`[database] Error connecting to MongoDB: ${error.message}`);
    // Do not call process.exit(1) to allow the container to start and listen.
    // Rethrow to let caller handle it.
    throw error;
  }
};

module.exports = connectDB;

