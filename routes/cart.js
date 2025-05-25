const express = require('express');
const { check } = require('express-validator');
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const authMiddleware = require('../middleware/auth');
const validate = require('../middleware/validate');
const sanitize = require('../middleware/sanitize');
const router = express.Router();

router.get('/', authMiddleware(), async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.id }).populate('items.product');
    if (!cart) {
      return res.json({ items: [] });
    }
    res.json(cart);
  } catch (err) {
    console.error('Get cart error:', err);
    res.status(500).json({ msg: 'Server error fetching cart' });
  }
});

router.post(
  '/',
  authMiddleware(),
  sanitize(),
  [
    check('productId').isMongoId().withMessage('Invalid product ID'),
    check('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
  ],
  validate,
  async (req, res) => {
    const { productId, quantity } = req.body;
    try {
      const product = await Product.findById(productId);
      if (!product) {
        return res.status(404).json({ msg: 'Product not found' });
      }
      let cart = await Cart.findOne({ user: req.user.id });
      if (!cart) {
        cart = new Cart({ user: req.user.id, items: [] });
      }
      const itemIndex = cart.items.findIndex((item) => item.product.toString() === productId);
      if (itemIndex > -1) {
        cart.items[itemIndex].quantity += quantity;
      } else {
        cart.items.push({ product: productId, quantity });
      }
      cart.updatedAt = Date.now();
      await cart.save();
      await cart.populate('items.product');
      res.json(cart);
    } catch (err) {
      console.error('Add to cart error:', err);
      res.status(500).json({ msg: 'Server error adding to cart' });
    }
  }
);

router.delete('/:productId', authMiddleware(), async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.id });
    if (!cart) {
      return res.status(404).json({ msg: 'Cart not found' });
    }
    cart.items = cart.items.filter((item) => item.product.toString() !== req.params.productId);
    await cart.save();
    await cart.populate('items.product');
    res.json(cart);
  } catch (err) {
    console.error('Remove from cart error:', err);
    res.status(500).json({ msg: 'Server error removing from cart' });
  }
});

module.exports = router;