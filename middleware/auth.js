const jwt = require('jsonwebtoken');

const authMiddleware = () => async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Auth middleware error:', {
      errorName: err.name,
      errorMessage: err.message,
      token,
    });
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ msg: 'Token expired, please refresh or re-login' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ msg: 'Invalid token format or signature' });
    }
    res.status(401).json({ msg: 'Invalid token' });
  }
};

module.exports = authMiddleware;