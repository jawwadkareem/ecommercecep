const express = require('express');
const { check } = require('express-validator');
const authMiddleware = require('../middleware/auth');
const validate = require('../middleware/validate');
const sanitize = require('../middleware/sanitize');
const router = express.Router();

router.post(
  '/process',
  authMiddleware(),
  sanitize(),
  [
    check('orderId').isMongoId().withMessage('Invalid order ID'),
    check('amount').isFloat({ min: 0 }).withMessage('Amount must be a positive number'),
  ],
  validate,
  async (req, res) => {
    const { orderId, amount } = req.body;
    try {
      // Placeholder for payment processing (e.g., Stripe integration)
      res.json({ msg: 'Payment processed successfully', orderId, amount });
    } catch (err) {
      console.error('Process payment error:', err);
      res.status(500).json({ msg: 'Server error processing payment' });
    }
  }
);

module.exports = router;