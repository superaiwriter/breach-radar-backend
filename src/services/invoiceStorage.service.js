const fs = require('fs');
const path = require('path');
const logger = require('../config/logger');

class InvoiceStorageService {
  constructor() {
    this.localDir = path.join(process.cwd(), 'uploads', 'invoices');
    this.ensureLocalDirectory();
  }

  ensureLocalDirectory() {
    try {
      if (!fs.existsSync(this.localDir)) {
        fs.mkdirSync(this.localDir, { recursive: true });
        logger.info(`[invoice-storage] Created directory: ${this.localDir}`);
      }
    } catch (error) {
      logger.error(`[invoice-storage] Failed to create local directory: ${error.message}`);
    }
  }

  /**
   * Save invoice PDF buffer to persistent storage.
   * @param {string} invoiceNumber - The unique invoice number.
   * @param {Buffer} pdfBuffer - The compiled PDF buffer.
   * @returns {Promise<{ pdfUrl: string, storageProvider: string }>}
   */
  async saveInvoicePdf(invoiceNumber, pdfBuffer) {
    const provider = process.env.STORAGE_PROVIDER || 'local';
    const filename = `${invoiceNumber}.pdf`;

    if (provider === 's3') {
      logger.info(`[invoice-storage] S3 storage provider selected. (Mocking S3 upload for future compatibility)`);
      // Future implementation for AWS S3 upload would go here.
      // const s3Url = await uploadToS3(filename, pdfBuffer);
      // For now, fall back or mock:
    }

    // Default to local storage
    const filePath = path.join(this.localDir, filename);
    try {
      fs.writeFileSync(filePath, pdfBuffer);
      
      const backendUrl = process.env.BACKEND_URL;
      if (!backendUrl) {
        logger.error('[invoice-storage] BACKEND_URL is not configured in environment variables for stored PDF URLs.');
      }
      const safeBackendUrl = (backendUrl || '').replace(/\/+$/, '');
      const pdfUrl = `${safeBackendUrl}/uploads/invoices/${filename}`;
      
      logger.info(`[invoice-storage] Saved invoice locally to: ${filePath}`);
      return {
        pdfUrl,
        storageProvider: 'local'
      };
    } catch (error) {
      logger.error(`[invoice-storage] Failed to save invoice PDF locally: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get invoice file as stream/buffer from storage.
   * @param {string} invoiceNumber - The invoice number to retrieve.
   * @returns {Promise<Buffer>}
   */
  async getInvoicePdf(invoiceNumber) {
    const filename = `${invoiceNumber}.pdf`;
    const filePath = path.join(this.localDir, filename);
    
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath);
    }
    throw new Error('Invoice file not found in persistent storage.');
  }
}

module.exports = new InvoiceStorageService();
