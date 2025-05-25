const { body } = require('express-validator');
const sanitizeHtml = require('sanitize-html');

const sanitize = () => {
  return [
    // Sanitize string fields to prevent XSS and injection attacks
    body('*').customSanitizer((value, { path }) => {
      if (typeof value === 'string') {
        // Trim and sanitize HTML
        const cleanValue = sanitizeHtml(value, {
          allowedTags: [], 
          allowedAttributes: {},
        }).trim();
        return cleanValue;
      }
      return value;
    }),
  ];
};

module.exports = sanitize;