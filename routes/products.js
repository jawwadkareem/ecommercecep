const express = require('express');
const { check } = require('express-validator');
const validator = require('validator');
const Product = require('../models/Product');
const Category = require('../models/Category');
const authMiddleware = require('../middleware/auth');
const adminMiddleware = require('../middleware/admin');
const validate = require('../middleware/validate');
const sanitize = require('../middleware/sanitize');
const AuditLog = require('../models/AuditLog');
const router = express.Router();

router.get('/', async (req, res) => {
  const { category, search } = req.query;
  try {
    const query = {};
    if (category) {
      query.category = category;
    }
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
      ];
    }
    const products = await Product.find(query).populate('category');
    res.json(products);
  } catch (err) {
    console.error('Get products error:', err);
    res.status(500).json({ msg: 'Server error fetching products' });
  }
});

router.get('/categories', async (req, res) => {
  try {
    const categories = await Category.find();
    res.json(categories);
  } catch (err) {
    console.error('Get categories error:', err);
    res.status(500).json({ msg: 'Server error fetching categories' });
  }
});

router.post(
  '/',
  authMiddleware(),
  adminMiddleware(),
  sanitize(),
  [
    check('name').trim().isLength({ min: 2, max: 100 }).withMessage('Product name must be between 2 and 100 characters'),
    check('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
    check('description').optional().trim().isLength({ max: 500 }).withMessage('Description cannot exceed 500 characters'),
    check('image').optional().custom((value) => {
      if (value && !validator.isURL(value)) {
        throw new Error('Invalid image URL');
      }
      return true;
    }),
    check('category').isMongoId().withMessage('Invalid category ID'),
  ],
  validate,
  async (req, res) => {
    const { name, price, description, image, category } = req.body;
    try {
      const categoryExists = await Category.findById(category);
      if (!categoryExists) {
        return res.status(400).json({ msg: 'Category not found' });
      }
      const product = new Product({ name, price, description, image, category });
      await product.save();
      await AuditLog.create({ user: req.user.id, action: 'create-product', details: `Product ${name} created` });
      res.status(201).json(product);
    } catch (err) {
      console.error('Create product error:', err);
      res.status(500).json({ msg: 'Server error creating product' });
    }
  }
);

router.put(
  '/:id',
  authMiddleware(),
  adminMiddleware(),
  sanitize(),
  [
    check('name').trim().isLength({ min: 2, max: 100 }).withMessage('Product name must be between 2 and 100 characters'),
    check('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
    check('description').optional().trim().isLength({ max: 500 }).withMessage('Description cannot exceed 500 characters'),
    check('image').optional().custom((value) => {
      if (value && !validator.isURL(value)) {
        throw new Error('Invalid image URL');
      }
      return true;
    }),
    check('category').isMongoId().withMessage('Invalid category ID'),
  ],
  validate,
  async (req, res) => {
    const { name, price, description, image, category } = req.body;
    try {
      const categoryExists = await Category.findById(category);
      if (!categoryExists) {
        return res.status(400).json({ msg: 'Category not found' });
      }
      const product = await Product.findById(req.params.id);
      if (!product) {
        return res.status(404).json({ msg: 'Product not found' });
      }
      product.name = name;
      product.price = price;
      product.description = description;
      product.image = image;
      product.category = category;
      await product.save();
      await AuditLog.create({ user: req.user.id, action: 'update-product', details: `Product ${name} updated` });
      res.json(product);
    } catch (err) {
      console.error('Update product error:', err);
      res.status(500).json({ msg: 'Server error updating product' });
    }
  }
);

router.delete('/:id', authMiddleware(), adminMiddleware(), async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ msg: 'Product not found' });
    }
    await product.remove();
    await AuditLog.create({ user: req.user.id, action: 'delete-product', details: `Product ${product.name} deleted` });
    res.json({ msg: 'Product deleted' });
  } catch (err) {
    console.error('Delete product error:', err);
    res.status(500).json({ msg: 'Server error deleting product' });
  }
});

router.post(
  '/categories',
  authMiddleware(),
  adminMiddleware(),
  sanitize(),
  [
    check('name').trim().isLength({ min: 2, max: 50 }).withMessage('Category name must be between 2 and 50 characters'),
  ],
  validate,
  async (req, res) => {
    const { name } = req.body;
    try {
      const category = new Category({ name });
      await category.save();
      await AuditLog.create({ user: req.user.id, action: 'create-category', details: `Category ${name} created` });
      res.status(201).json(category);
    } catch (err) {
      console.error('Create category error:', err);
      res.status(500).json({ msg: 'Server error creating category' });
    }
  }
);

module.exports = router;