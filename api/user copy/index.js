'use strict';

const express = require('express');
const controller = require('./user.controller');
const auth = require('../../auth/auth.service');

const router = express.Router();

router.post('/', controller.create);
router.post('/auth', controller.authenticate);
router.get('/verifyIP/:ip', controller.verifyIP);
router.put('/setPassword', controller.setPassword); 
router.get('/act/:act_code', controller.verifyemail); 
router.post('/validateUname', controller.validateUname); 
router.post('/forgotPassword', controller.forgotPassword);
router.get('/validateKey/:tempPass', controller.validateKey);
router.post('/resendVerification', controller.resendVerification);
router.get('/myProfile', auth.isAuthenticated(), controller.myProfile); 
router.get('/sendSmsAuth', auth.isAuthenticated(), controller.sendSmsAuth);
router.get('/myReferences', auth.isAuthenticated(), controller.myReferences);
router.put('/updateProfile', auth.isAuthenticated(), controller.updateProfile);
router.get('/verifySmsAuth', auth.isAuthenticated(), controller.verifySmsAuth);
router.get('/disableSmsAuth', auth.isAuthenticated(), controller.disableSmsAuth);
router.put('/changePassword', auth.isAuthenticated(), controller.changePassword);
router.get('/kyc', auth.isAuthenticated(), auth.isVerified(), controller.getKycInfo); 
router.post('/saveKyc', auth.isAuthenticated(), auth.isVerified(), controller.saveKyc);
router.get('/enable2Factor', auth.isAuthenticated(), auth.isVerified(), controller.enable2Factor);
router.post('/enableSmsAuth', auth.isAuthenticated(), auth.isVerified(), controller.enableSmsAuth);
router.post('/verify2Factor', auth.isAuthenticated(), auth.isVerified(), controller.verify2Factor); 
router.get('/disable2Factor', auth.isAuthenticated(), auth.isVerified(), controller.disable2Factor); 
router.put('/trackme/:status', auth.isAuthenticated(), auth.isVerified(), controller.updateTracking);
router.post('/verify_backup_code', auth.isAuthenticated(), auth.isVerified(), controller.verify_backup_code);

router.post('/stats', auth.hasRole('kycAdmin'), controller.stats);
router.post('/list', auth.hasRole('kycAdmin'), controller.listUsers);
router.post('/kycStatus', auth.hasRole('kycAdmin'), controller.kycStatus);
router.post('/getKycUsers', auth.hasRole('kycAdmin'), controller.getKycUsers);

router.get('/referralCron', controller.referralCron);
router.post('/addAffiliate', auth.hasRole('admin'), controller.create);
router.get('/referralStats', auth.hasRole('affiliateAdmin'), controller.referralStats);

router.post('/search', auth.isAuthenticated(), controller.search);

// router.post('/testMail', controller.testMail);

module.exports = router;
