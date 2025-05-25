const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 50 },
});

module.exports = mongoose.model('Category', categorySchema);