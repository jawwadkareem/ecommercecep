const express = require('express');
const { check } = require('express-validator');
const Order = require('../models/Order');
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const authMiddleware = require('../middleware/auth');
const validate = require('../middleware/validate');
const sanitize = require('../middleware/sanitize');
const router = express.Router();

router.get('/', authMiddleware(), async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user.id }).populate('items.product');
    res.json(orders);
  } catch (err) {
    console.error('Get orders error:', err);
    res.status(500).json({ msg: 'Server error fetching orders' });
  }
});

router.post(
  '/',
  authMiddleware(),
  sanitize(),
  [
    check('items').isArray({ min: 1 }).withMessage('At least one item is required'),
    check('items.*.product').isMongoId().withMessage('Invalid product ID'),
    check('items.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
  ],
  validate,
  async (req, res) => {
    const { items } = req.body;
    try {
      const productIds = items.map((item) => item.product);
      const products = await Product.find({ _id: { $in: productIds } });
      if (products.length !== productIds.length) {
        return res.status(404).json({ msg: 'One or more products not found' });
      }
      const total = items.reduce((sum, item) => {
        const product = products.find((p) => p._id.toString() === item.product);
        return sum + product.price * item.quantity;
      }, 0);
      const order = new Order({
        user: req.user.id,
        items,
        total,
      });
      await order.save();
      await Cart.findOneAndUpdate({ user: req.user.id }, { items: [], updatedAt: Date.now() });
      await order.populate('items.product');
      res.status(201).json(order);
    } catch (err) {
      console.error('Create order error:', err);
      res.status(500).json({ msg: 'Server error creating order' });
    }
  }
);

module.exports = router;