const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true, trim: true, maxlength: 50 },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  address: { type: String, trim: true, maxlength: 200 },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
});

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

module.exports = mongoose.model('User', userSchema);