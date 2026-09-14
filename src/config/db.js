const mongoose = require('mongoose');
const logger = require('./logger');
// Set fallback DNS servers only if custom DNS is explicitly requested
if (process.env.CUSTOM_DNS_SERVERS) {
  try {
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

    logger.info('Connecting to MongoDB...');
    
    const conn = await mongoose.connect(connUri, {
      autoIndex: !isProduction, // Build indexes in dev. Turn off in heavy prod.
      serverSelectionTimeoutMS: 10000,
    });

    logger.info(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    logger.error(`Error connecting to MongoDB: ${error.message}`);
    // Do not call process.exit(1) to allow the container to start and listen.
    // Rethrow to let the caller handle it.
    throw error;
  }
};

module.exports = connectDB;
