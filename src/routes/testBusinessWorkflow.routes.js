const express = require('express');
const router = express.Router();

// Simple in-memory session/state store keyed by cartId
const cartStates = {};

// Helper to extract parameters from either query or body
const getParams = (req) => {
  return {
    cartId: req.body.cartId || req.query.cartId,
    quantity: req.body.quantity || req.query.quantity
  };
};

// =========================================================================
// VULNERABLE WORKFLOW (No workflow state enforcement, no param validation)
// =========================================================================

// Step 1: Create Cart
router.all('/vulnerable/cart', (req, res) => {
  const cartId = 'vuln_' + Math.random().toString(36).substring(2, 11);
  cartStates[cartId] = 'cart-created';
  res.json({ success: true, cartId, step: 'cart', message: 'Cart created successfully.' });
});

// Step 2: Add Product (accepts invalid parameters like negative/zero quantity)
router.all('/vulnerable/add-product', (req, res) => {
  const { cartId, quantity } = getParams(req);
  if (cartId) {
    cartStates[cartId] = 'product-added';
  }
  // Vulnerable: no parameter validation on quantity
  res.json({
    success: true,
    cartId,
    quantity: quantity !== undefined ? Number(quantity) : 1,
    step: 'add-product',
    message: 'Product added to cart.'
  });
});

// Step 3: Checkout
router.all('/vulnerable/checkout', (req, res) => {
  const { cartId } = getParams(req);
  if (cartId) {
    cartStates[cartId] = 'checkout-completed';
  }
  res.json({ success: true, cartId, step: 'checkout', message: 'Checkout step completed.' });
});

// Step 4: Confirm (accepts bypass/direct calls without correct workflow state)
router.all('/vulnerable/confirm', (req, res) => {
  // Vulnerable: confirm is processed even if checkout state check is missing or incomplete
  res.json({
    success: true,
    step: 'confirm',
    message: 'Order confirmed successfully.',
    evidence: 'Vulnerability: checkout confirmation was accepted without checking workflow state.'
  });
});

// =========================================================================
// SECURE WORKFLOW (Enforces strict workflow state transitions & validations)
// =========================================================================

// Step 1: Create Cart
router.all('/secure/cart', (req, res) => {
  const cartId = 'sec_' + Math.random().toString(36).substring(2, 11);
  cartStates[cartId] = 'cart-created';
  res.json({ success: true, cartId, step: 'cart', message: 'Cart created successfully.' });
});

// Step 2: Add Product (validates cart step & quantity parameter)
router.all('/secure/add-product', (req, res) => {
  const { cartId, quantity } = getParams(req);

  if (!cartId || cartStates[cartId] !== 'cart-created') {
    return res.status(400).json({
      success: false,
      error: 'Invalid workflow transition. Cart must be created first.'
    });
  }

  // Validate parameter: quantity must be positive
  const parsedQty = parseInt(quantity, 10);
  if (isNaN(parsedQty) || parsedQty <= 0) {
    return res.status(400).json({
      success: false,
      error: 'Invalid quantity parameter. Quantity must be a positive integer.'
    });
  }

  cartStates[cartId] = 'product-added';
  res.json({
    success: true,
    cartId,
    quantity: parsedQty,
    step: 'add-product',
    message: 'Product added successfully.'
  });
});

// Step 3: Checkout (validates product-added step)
router.all('/secure/checkout', (req, res) => {
  const { cartId } = getParams(req);

  if (!cartId || cartStates[cartId] !== 'product-added') {
    return res.status(400).json({
      success: false,
      error: 'Invalid workflow transition. Must add products to cart before checkout.'
    });
  }

  cartStates[cartId] = 'checkout-completed';
  res.json({ success: true, cartId, step: 'checkout', message: 'Checkout step completed.' });
});

// Step 4: Confirm (validates checkout-completed step)
router.all('/secure/confirm', (req, res) => {
  const { cartId } = getParams(req);

  if (!cartId || cartStates[cartId] !== 'checkout-completed') {
    return res.status(403).json({
      success: false,
      error: 'Access denied. Order confirmation requires completing the checkout step.'
    });
  }

  res.json({ success: true, cartId, step: 'confirm', message: 'Order confirmed successfully.' });
});

module.exports = router;
