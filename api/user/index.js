'use strict';

const express = require('express');
const controller = require('./user.controller');
const auth = require('../../auth/auth.service');

const router = express.Router();

router.post('/', controller.create);
router.post('/auth', controller.authenticate);

router.get('/verifyIP/:ip', controller.verifyIP);
router.get('/verifyEmail/:actCode', controller.verifyEmail); 
router.post('/resendVerification', controller.resendVerification);

router.get('/myProfile', auth.isAuthenticated(), controller.myProfile); 
router.put('/updateProfile', auth.isAuthenticated(), controller.updateProfile);

router.put('/setPassword', controller.setPassword); 
router.post('/forgotPassword', controller.forgotPassword);
router.get('/passwordKey/:tempPass', controller.passwordKey);
router.put('/changePassword', auth.isAuthenticated(), controller.changePassword);

router.get('/sendSmsAuth', auth.isAuthenticated(), controller.sendSmsAuth);
router.get('/verifySmsAuth', auth.isAuthenticated(), controller.verifySmsAuth);
router.get('/disableSmsAuth', auth.isAuthenticated(), controller.disableSmsAuth);
router.post('/enableSmsAuth', auth.isAuthenticated(), auth.isVerified(), controller.enableSmsAuth);

router.get('/enable2Factor', auth.isAuthenticated(), auth.isVerified(), controller.enable2Factor);
router.post('/verify2Factor', auth.isAuthenticated(), auth.isVerified(), controller.verify2Factor); 
router.get('/disable2Factor', auth.isAuthenticated(), auth.isVerified(), controller.disable2Factor); 
router.post('/verifyBackupCode', auth.isAuthenticated(), auth.isVerified(), controller.verifyBackupCode);

module.exports = router;