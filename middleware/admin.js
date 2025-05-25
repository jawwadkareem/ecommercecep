const User = require('../models/User');

const adminMiddleware = () => async (req, res, next) => {
  try {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ msg: 'Unauthorized: No user authenticated' });
    }
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }
    if (user.role !== 'admin') {
      return res.status(403).json({ msg: 'Forbidden: Admin access required' });
    }
    next();
  } catch (err) {
    console.error('Admin middleware error:', err);
    res.status(500).json({ msg: 'Server error in admin verification' });
  }
};

module.exports = adminMiddleware;