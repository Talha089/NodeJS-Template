'use strict';

const mongoose = require('mongoose');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const compose = require('composable-middleware');

const User = require('../api/user/user.model');
const config = require('../config/environment');
const Logging = require('../api/logging/logging.model');

const validateJwt = expressJwt({ secret: config.secrets.session });

                        /**
                          * Attaches the user object to the request if authenticated
                          * Otherwise returns 403
                        */
function isAuthenticated()
{
  return compose()
                                            // Validate jwt
    .use((req, res, next)=>
    {
      if (!req.headers.authorization)
        return res.status(200).send({status:'failure',data:[],msg:'Please login to perform this action'});

                        // allow access_token to be passed through query parameter as well

      if(req.query && req.query.hasOwnProperty('access_token')) 
        req.headers.authorization = 'Bearer ' + req.query.access_token;
      validateJwt(req, res, next);
    })
                                          // Attach user to request
    .use((req, res, next)=>
    {
      User.findById(req.user._id, (err, user)=>
      {
        if (err)
          return next(err);
        if (!user)
          return res.status(200).send({status:'failure',data:[],msg:'Unauthorized'});
        Logging.find({user_id:user._id,request_url:'/api/users/auth'},{ip_address:1,access_time:1}).skip(1).limit(1).sort({access_time: -1}).exec(function(er1,logger)
        {
          req.user = user;
          if (logger.length > 0)
            req.logger = logger[0];
          next();
        });
      });
    });
}

                  /**
                    * Checks if the user role meets the minimum requirements of the route
                  */
function hasRole(roleRequired)
{
  if (!roleRequired) throw new Error('Required role needs to be set');

  return compose()
    .use(isAuthenticated())
    .use(function meetsRequirements(req, res, next)
    {
      if (config.userRoles.indexOf(req.user.role) >= config.userRoles.indexOf(roleRequired))
        next();
      else
        res.status(403).send('Forbidden');
    });
}

                          /**
                            * Returns a jwt token signed by the app secret
                          */
function signToken(id)
{
  return jwt.sign({ _id: id }, config.secrets.session, { expiresIn: 60 * 60 * 5 });
}

                          /**
                            * Set token cookie directly for oAuth strategies
                          */
function setTokenCookie(req, res)
{
  if (!req.user)
    return res.status(404).json({ status:'failure',data:[],msg:'Something went wrong, please try again.'});
  let token = signToken(req.user._id, req.user.role);
  res.cookie('token', JSON.stringify(token));
  res.redirect('/');
}

                        /**
                         * Checks if the user has verified email or not.
                        */
function isVerified()
{
  return compose()
    .use(isAuthenticated())
    .use(function meetsRequirements(req, res, next)
    {
      if (req.user.email_verified)
        next();
      else
        return res.json({status:'failure',data:[],msg:'Please verify your email to proceed.'});
    });
}

                      /**
                        * function for checking kyc status of user
                      */
function isKycVerified()
{
  return compose()
    .use(isAuthenticated())
    .use(function meetsRequirements(req, res, next)
    {
      if (req.user.is_kyc_verified == 'Verified')
        next();
      else
      {
        if (req.user.is_kyc_verified == 'InComplete')
          return res.json({status:'failure',data:[],msg:'Please submit kyc details. Only KYC verified users are allowed to perform this action.'});
        else if(req.user.is_kyc_verified == 'Pending')
          return res.json({status:'failure',data:[],msg:'Please update kyc details or Please allow us sometime to get your kyc verified by admin'});
        else
          return res.json({status:'failure',data:[],msg:'Only KYC verified users are allowed to perform this action.'});
      }
    });
}

                        /**
                          * Checks if the secret key from client matches with server's
                        */
function pepper()
{
  return compose()
    .use(isAuthenticated())
    .use(function meetsRequirements(req, res, next)
    {
      if (config.pepper === req.body.exchange)
        next();
      else
        res.status(403).send('Forbidden');
    });
}

                                    //check if pin is valid or not
function verifyPin()
{
  return compose()
    .use(isAuthenticated())
    .use(function meetsRequirements(req, res, next)
    {
      console.log(req.body);
      
      if (!req.body.auth_pin)
        return res.json({status:'failure',data:[],msg:'Please provide PIN to proceed'});
      else if (!req.user.auth_pin)
        return res.json({status:'failure',data:[],msg:'Please setup authentication PIN to proceed'});
      else if (req.body.auth_pin && (req.user.auth_pin == req.body.auth_pin))
        next();
      else
        return res.json({status:'failure',data:[],msg:'Please provide valid PIN to proceed'});
    });
}

exports.isAuthenticated = isAuthenticated;
exports.hasRole = hasRole;
exports.signToken = signToken;
exports.setTokenCookie = setTokenCookie;
exports.isVerified = isVerified;
exports.isKycVerified = isKycVerified;
exports.pepper = pepper;
exports.verifyPin = verifyPin;