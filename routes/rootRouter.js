const express = require('express');
const AppError = require('./../utils/appError');
const catchAsync = require('./../utils/catchAsync');

const router = express.Router();

router.route('/').get(
  catchAsync(async (req, res, next) => {
    res.status(200).json({
      status: 'success',
      data: {
        message: 'Welcome to Abhishek Kumar Sings Website. Production is in process will be live soon......'
      }
    });
  })
);
module.exports = router;
