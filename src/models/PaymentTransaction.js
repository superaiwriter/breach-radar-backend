const mongoose = require('mongoose');

const PaymentTransactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  organizationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true,
  },
  subscriptionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Subscription',
  },
  invoiceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Invoice',
  },
  provider: {
    type: String,
    enum: ['manual', 'razorpay', 'stripe', 'paypal'],
    default: 'manual',
    index: true,
  },
  providerOrderId: {
    type: String,
    default: '',
  },
  providerPaymentId: {
    type: String,
    default: '',
  },
  transactionId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  amount: {
    type: Number,
    required: true,
    min: 0,
  },
  currency: {
    type: String,
    default: 'INR',
  },
  status: {
    type: String,
    enum: ['created', 'pending', 'succeeded', 'failed', 'refunded'],
    default: 'created',
    index: true,
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model('PaymentTransaction', PaymentTransactionSchema);
