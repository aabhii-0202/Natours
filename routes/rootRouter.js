const express = require('express');
const AppError = require('./../utils/appError');
const catchAsync = require('./../utils/catchAsync');

const router = express.Router();

router.route('/').get(
  catchAsync(async (req, res, next) => {
    res.status(200).json({
      status: 'success',
      data: {
        message: 'Server running successful'
      }
    });
  })
);
module.exports = router;
