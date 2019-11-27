                                  /**
                                     * Using Rails-like standard naming convention for endpoints.
                                     * GET     /loggings              ->  index
                                     * POST    /loggings              ->  create
                                     * GET     /loggings/:id          ->  show
                                     * PUT     /loggings/:id          ->  update
                                     * DELETE  /loggings/:id          ->  destroy
                                  */

'use strict';

const Logging = require('./logging.model');
const util = require('../../utils/encryption.util');

function newlog(req,uid='')
{
  if (req.user) uid = req.user._id;
  let token = req.headers.authorization ? req.headers.authorization : '';
  let can_track = req.user ? req.user.can_track : false;
  let logObj = new Logging({
    userId : uid,
    ipAddress : process.env.IP,
    userAgent : req.headers['user-agent'],
    accessToken : token,
    accessTime : new Date(),
    requestUrl : req.originalUrl,
    requestData : util.encryptdata(JSON.stringify(req.body)),
    track : can_track
  });
  logObj.save();
}

                                            //GET login history
exports.loginHistory = (req, res)=>
{
    Logging.find({userId: req.user._id, requestUrl: '/api/users/auth'},{ipAddress: 1, accessTime:1, userAgent: 1}).lean().sort({accessTime:-1}).exec((err, logs)=>
    {
        if (err) return handleError(res, err);
        return res.json({status: true,data:logs,msg:'Login history'});
    });
}

function handleError(res, err)
{
    return res.status(500).send(err);
}

exports.newlog = newlog;