'use strict';

const router = require('express').Router();
const auth = require('../../auth/auth.service');
const controller = require('./property.controller');

router.get('/:id', controller.getProperty);
router.post('/', auth.isAuthenticated(), auth.isVerified(), controller.create);
router.get('/', auth.isAuthenticated(), auth.isVerified(), controller.myProperties);
router.post('/update', auth.isAuthenticated(), auth.isVerified(), controller.updateProperty);

module.exports = router;