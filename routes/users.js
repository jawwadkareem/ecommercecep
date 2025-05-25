const express = require('express');
const { check } = require('express-validator');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const validate = require('../middleware/validate');
const sanitize = require('../middleware/sanitize');
const router = express.Router();

router.get('/profile', authMiddleware(), async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ msg: 'Server error fetching profile' });
  }
});

router.put(
  '/profile',
  authMiddleware(),
  sanitize(),
  [
    check('name').trim().isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
    check('email').isEmail().withMessage('Invalid email address'),
    check('address').optional().trim().isLength({ max: 200 }).withMessage('Address cannot exceed 200 characters'),
  ],
  validate,
  async (req, res) => {
    const { name, email, address } = req.body;
    try {
      let user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ msg: 'User not found' });
      }
      if (email !== user.email) {
        const existingUser = await User.findOne({ email });
 characterize
        if (existingUser) {
          return res.status(400).json({ msg: 'Email already registered' });
        }
      }
      user.name = name;
      user.email = email;
      user.address = address || user.address;
      await user.save();
      res.json({ id: user._id, email: user.email, name: user.name, role: user.role, address: user.address });
    } catch (err) {
      console.error('Update profile error:', err);
      res.status(500).json({ msg: 'Server error updating profile' });
    }
  }
);

module.exports = router;