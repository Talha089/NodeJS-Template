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
  if (req.user)
    uid = req.user._id;

  let token = req.headers.authorization ? req.headers.authorization : '';
  let can_track = req.user ? req.user.can_track : false;
  let logObj = {
    userId : uid,
    ipAddress : req.clientIp,
    user_agent : req.headers['user-agent'],
    access_token : token,
    access_time : new Date(),
    request_url : req.originalUrl,
    // request_data : util.encryptdata(JSON.stringify(req.body)),
    track : can_track
  };
  let finalLog = new Logging(logObj);
  finalLog.save((err, saved)=>{});
}

                                            //GET login history
exports.loginHistory = (req, res)=>
{
    Logging.find({userId:req.user._id,request_url:'/api/users/auth'},{ipAddress:1,access_time:1,user_agent:1}).lean().sort({access_time:-1}).exec((err, logs)=>
    {
        if (err)
            return handleError(res, err);
        return res.json({status:'success',data:logs,msg:'Login history'});
    });
}

function handleError(res, err)
{
    return res.status(500).send(err);
}

exports.newlog = newlog;