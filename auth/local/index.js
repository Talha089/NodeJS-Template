'use strict';

var express = require('express');
var passport = require('passport');
var auth = require('../auth.service');

var router = express.Router();

router.post('/', function(req, res, next)
{
  passport.authenticate('local', function (err, user, info)
  {
    var error = err || info;
    if (error) return res.status(401).json({status:'failure',data:error,msg:'Something went wrong, please try again'});
    if (!user) return res.status(404).json({status:'failure',data:[],msg:'Something went wrong, please try again.'});

    var token = auth.signToken(user._id, user.role);
    res.json({status:'success',data:{token: token},msg:'Successfully logged in'});
  })(req, res, next)
});

module.exports = router;