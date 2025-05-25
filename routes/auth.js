const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { check } = require('express-validator');
const validator = require('validator');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const validate = require('../middleware/validate');
const sanitize = require('../middleware/sanitize');
const authMiddleware = require('../middleware/auth');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const router = express.Router();

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

router.post(
  '/register',
  sanitize(),
  [
    check('email').isEmail().withMessage('Invalid email address'),
    check('name').trim().isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
    check('password').custom((value) => {
      if (!validator.isStrongPassword(value, { minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 })) {
        throw new Error(
          'Password must be at least 8 characters long, include uppercase and lowercase letters, a number, and a special character'
        );
      }
      return true;
    }),
    check('role')
      .optional()
      .isIn(['user', 'admin'])
      .withMessage('Role must be either "user" or "admin"'),
    check('adminSecret')
      .optional()
      .custom((value, { req }) => {
        if (req.body.role === 'admin' && value !== process.env.ADMIN_SECRET) {
          throw new Error('Invalid admin secret');
        }
        return true;
      }),
  ],
  validate,
  async (req, res) => {
    const { email, password, name, role = 'user', adminSecret } = req.body;
    try {
      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ msg: 'Email already registered' });
      }
      user = new User({
        email,
        password,
        name,
        role: role === 'admin' && adminSecret === process.env.ADMIN_SECRET ? 'admin' : 'user',
      });
      await user.save();
      await AuditLog.create({ user: user._id, action: 'register', details: `User ${email} registered as ${user.role}` });
      const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
      const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      res.json({ token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).json({ msg: 'Server error during registration' });
    }
  }
);

router.post(
  '/login',
  sanitize(),
  [
    check('email').isEmail().withMessage('Invalid email address'),
    check('password').notEmpty().withMessage('Password is required'),
  ],
  validate,
  async (req, res) => {
    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ msg: 'Invalid email or password' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ msg: 'Invalid email or password' });
      }
      const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
      const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      await AuditLog.create({ user: user._id, action: 'login', details: `User ${email} logged in` });
      res.json({ token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ msg: 'Server error during login' });
    }
  }
);

router.post('/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ msg: 'No refresh token provided' });
  }
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ msg: 'Invalid refresh token: User not found' });
    }
    const newToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.json({ token: newToken });
  } catch (err) {
    console.error('Refresh token error:', {
      errorName: err.name,
      errorMessage: err.message,
      refreshToken,
    });
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ msg: 'Refresh token expired, please re-login' });
    }
    res.status(401).json({ msg: 'Invalid refresh token' });
  }
});

router.post(
  '/forgot-password',
  sanitize(),
  [check('email').isEmail().withMessage('Invalid email address')],
  validate,
  async (req, res) => {
    const { email } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ msg: 'Email not registered' });
      }
      const resetToken = crypto.randomBytes(20).toString('hex');
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 3600000;
      await user.save();
      const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
      await transporter.sendMail({
        to: email,
        subject: 'Password Reset',
        html: `Click <a href="${resetUrl}">here</a> to reset your password. Link expires in 1 hour.`,
      });
      await AuditLog.create({ user: user._id, action: 'forgot-password', details: `Password reset requested for ${email}` });
      res.json({ msg: 'Password reset email sent' });
    } catch (err) {
      console.error('Forgot password error:', err);
      res.status(500).json({ msg: 'Error sending reset email' });
    }
  }
);

router.post(
  '/reset-password/:token',
  sanitize(),
  [check('password').custom((value) => {
    if (!validator.isStrongPassword(value, { minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 })) {
      throw new Error(
        'Password must be at least 8 characters long, include uppercase and lowercase letters, a number, and a special character'
      );
    }
    return true;
  })],
  validate,
  async (req, res) => {
    const { password } = req.body;
    const { token } = req.params;
    try {
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
      });
      if (!user) {
        return res.status(400).json({ msg: 'Invalid or expired reset token' });
      }
      user.password = password;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();
      await AuditLog.create({ user: user._id, action: 'reset-password', details: `Password reset for ${user.email}` });
      res.json({ msg: 'Password reset successful' });
    } catch (err) {
      console.error('Reset password error:', err);
      res.status(500).json({ msg: 'Error resetting password' });
    }
  }
);

router.get('/verify', authMiddleware(), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(401).json({ msg: 'User not found' });
    }
    res.json({ id: user._id, email: user.email, name: user.name, role: user.role });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(401).json({ msg: 'Invalid token' });
  }
});

router.get('/logout', async (req, res) => {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
  });
  res.json({ msg: 'Logged out' });
});

module.exports = router;