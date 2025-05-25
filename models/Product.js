const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  price: { type: Number, required: true, min: 0 },
  description: { type: String, trim: true, maxlength: 500 },
  image: { type: String, trim: true },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
});

module.exports = mongoose.model('Product', productSchema);