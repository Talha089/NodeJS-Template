'use strict';

const fs = require('fs');
const _ = require('lodash');
const async = require('async');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const speakeasy = require("speakeasy");

const User = require('./user.model');
const Referral = require('./referral.model');
const config = require('../../config/environment');
const Logging = require('../logging/logging.model');
const logging = require('../logging/logging.controller');
const client = require('twilio')(config.twillio.accountSid, config.twillio.authToken);

                                                    /**
                                                        * Creates a new user
                                                    **/
exports.create = (req, res, next) =>
{
    if (!req.body.name || req.body.name == '')
        return res.json({status:'failure',data:[],msg:'Please provide name'});
    if (!req.body.email || req.body.email == '')
        return res.json({status:'failure',data:[],msg:'Please provide email id'});
    if (!req.body.password || req.body.password == '')
        return res.json({status:'failure',data:[],msg:'Please provide password for your account'});
    if (!req.body.terms_cond || req.body.terms_cond == '')
        return res.json({status:'failure',data:[],msg:'Please read agree to terms and conditions to proceed'});
    if (validator.isEmail(req.body.email) === false) 
        return res.json({status:'failure',data:[],msg:'Please provide valid email id'});
    if (!req.body.uname || req.body.uname == '')
        return res.json({Status:'failure',data:[],msg:'Please provide username !!!'});
    
    const uname = req.body.uname.toLowerCase();
    const umail = req.body.email.toLowerCase();
    User.findOne({$or:[{email:umail},{uname: uname}]}, (err,userfound) =>
    {
        if (err) return handleError(res, err);
        if (userfound) 
            if (userfound.email == umail)
                return res.json({status:"failure",data:[],msg:"Email is already used !!!"});
            else
                return res.json({status:"failure",data:[],msg:"Username is already used !!!"});
        else
        {
            let randcode = "";
            let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (let i = 0; i < 15; i++)
                randcode += possible.charAt(Math.floor(Math.random() * possible.length));
        
            const act_code = randcode+randcode;

            let new_user_body = {
                name: req.body.name,
                email: umail,
                uname: uname,
                password: req.body.password,
                is_terms_accepted: req.body.terms_cond,
                provider : 'local',
                role: 'user',
                source: 'direct',
                email_verify_key: act_code
            }
            if (req.body.referral_code)
                new_user_body.referred_by = req.body.referral_code;
            if (req.body.is_affiliate)
                new_user_body.is_affiliate = req.body.is_affiliate;
            if (req.body.is_af_admin)
                new_user_body.role = 'affiliateAdmin';
            if (req.body.is_airdrop)
                new_user_body.is_airdrop = req.body.is_airdrop;
            if (req.body.telegram_username)
                new_user_body.telegram_username = req.body.telegram_username;
            if (req.body.twitter_username)
                new_user_body.twitter_username = req.body.twitter_username;

            const newUser = new User(new_user_body);
            newUser.save((err, user)=>
            {
                if (err) return validationError(res, err);

                let activation_link = config.clientdomain + '/verify_email/' + act_code;

                const templatePath = "server/mail_templates/sign_up.html";
                let templateContent = fs.readFileSync(templatePath, "utf8");
                templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
                templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
                templateContent = templateContent.replace("##USERNAME##", user.name);
                templateContent = templateContent.replace("##ACTIVATION_LINK##", activation_link);
                templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);

                const data = {
                    from: config.mail_from_email,
                    to: user.email,
                    subject: config.project_name + ' - Sign up',
                    html: templateContent
                }

                config.mailTransporter.sendMail(data, (error, info) =>
                {
                    if (error)
                        console.log(error);
                    else
                        console.log('Email sent:', info.envelope);
                });

                const token = jwt.sign({_id: user._id }, config.secrets.session, { expiresIn: 60*60*3, algorithm: 'HS256' });
                return res.json({ status:"success",data:{token: token },msg:'Registered successfully. Please confirm your Email !!'});
            });
        }
    })
};
                                                    /**
                                                        * Change a users password
                                                    **/
exports.changePassword = (req, res, next) =>
{
  const userId = req.user._id;
  const oldPass = String(req.body.oldPassword);
  const newPass = String(req.body.newPassword);

  if (!req.body.oldPassword || !req.body.newPassword || req.body.oldPassword == '' || req.body.newPassword == '')
    return res.json({status:'failure',data:[],msg:'Please provide password'});

  User.findById(userId, (err, user) =>
  {
    if(user.authenticate(oldPass))
    {
      user.password = newPass;
      user.save((err)=>
      {
        if (err) return validationError(res, err);

        const templatePath = "server/mail_templates/change_password.html";
        let templateContent = fs.readFileSync(templatePath, "utf8");
        templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
        templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
        templateContent = templateContent.replace("##USERNAME##", user.name);
        templateContent = templateContent.replace("##USERMAIL##", user.email);
        templateContent = templateContent.replace("##REQ_TIME##", new Date());
        templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);


        const data = {
            from: config.mail_from_email,
            to: user.email,
            subject: config.project_name + ' - Password Changed',
            html: templateContent
        }

        config.mailTransporter.sendMail(data, (error, info) =>
        {
            if (error)
                console.log(error);
            else
                console.log('Email sent:', info.envelope);
        });
        return res.json({status:'success',data:[],msg:'Password changed Successfully'});
      });
    }
    else
      return res.send({status:'failure',data:[],msg:'Incorrect current password'});
  });
};
                                                    /**
                                                        * Get my Profile
                                                    **/
exports.myProfile = (req, res, next)=>
{
    const userId = req.user._id;
    let query = User.findOne(
    {
        _id: userId
    }, '-salt -hashedPassword -temp_password -email_verify_key -two_fa_secret_key -provider -source').lean()
    query.lean().exec((err, user)=>
    {
        if (err) 
            return next(err);
        else if (!user)
            return res.status(401).json({status:'failure',data:[],msg:'Unauthorized'});
        else if (req.logger)
        {
            user.last_login = req.logger.access_time;
            user.last_login_from = req.logger.ip_address;
        }
        else
            return res.json({status:'success',data:user,msg:'Profile details'});
    });
};
                                                    /**
                                                        * Activate Account
                                                    **/
exports.verifyemail = (req, res)=>
{
    if (!req.params.act_code || req.params.act_code == '')
        return res.json({status:'failure',data:[],msg:'Invalid request. Please try again'})

    User.findOne({email_verify_key:req.params.act_code,email_verified:false},{},(err,userDetails)=>
    {
        if (err)
            return handleError(res, err);
            
        if (userDetails)
        {
            const date_now = new Date();

            function rand_code()
            {
                let randcode = "";
                let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                for (let i = 0; i < 6; i++)
                    randcode += possible.charAt(Math.floor(Math.random() * possible.length));
                return randcode+`${userDetails._id}`.substring(10,15);
            }

            const ref_code = rand_code();
            if (userDetails.referral_code)
                ref_code = userDetails.referral_code;

            User.updateOne({_id:userDetails._id},{$set:{email_verified:true,is_active:true,referral_code:ref_code,updated_by:userDetails._id,updated_at:date_now},$unset:{email_verify_key:1}}, (err1,status)=>
            {
                if (err1)
                    return handleError(res, err);
                
                if (status.nModified)
                {
                    if (userDetails.referred_by)
                        User.findOneAndUpdate({referral_code:userDetails.referred_by},{$inc:{referral_count: 1}}).exec();
                    
                    return res.json({status:'success',data:[],msg:'Successfully verified your email !!!'});
                }
                else
                    return res.json({status:'success',data:[],msg:'Something went wrong. Please try again !!!'});
            })
        }
        else
            return res.json({status:'failure',data:[],msg:'This link got expired !!!'});
    })
}
                                                    /**
                                                        * Authenticate User
                                                    **/
exports.authenticate = (req, res) =>
{
    if (!req.body.email || req.body.email == '')
        return res.json({status:'failure',data:[],msg:'Enter Email to Login !!'});
    if (!req.body.password || req.body.password == '')
        return res.json({status:'failure',data:[],msg:'Enter Password to Login !!'});
    
    User.findOne({email:req.body.email},{source:0},(err,userfound)=>
    {
        if (err) return handleError(res, err);
        if (userfound) 
        {
            if (!userfound.authenticate(req.body.password))
                return res.json({status:'failure',data:[],msg:'Invalid Password !!'});
            else if(!userfound.email_verified)
                return res.json({status:'failure',data:[],msg:'Please verify your email address to proceed.'});
            else
            {
                Logging.find({user_id:userfound._id, ip_address:req.clientIp}).exec((error, login)=>
                {
                    if(error) 
                        console.log("error");
                    else
                    {
                        if(login.length === 0)
                        {
                            configureIpNotification(req, userfound, (data)=>
                            {
                                return res.json({status:'failure', data:[], msg:'Please Verify your Device by email !!!'});
                            });
                        }
                        else
                        {
                            if (!userfound.two_fa_enable)
                            {
                                loginNotification(req, userfound, res, (cbData)=>
                                {
                                    return res.json({
                                        status:'success',
                                        data:{
                                            token:cbData.token,
                                            first_login:cbData.is_first_login,
                                            id:userfound._id,
                                            referral_code:cbData.ref_code,
                                            two_fa_enable:false,
                                            role:userfound.role
                                        },msg:'Login Sucessfull !!'});
                                });
                            }
                            else
                            {
                                const token = jwt.sign(
                                    {_id: userfound._id }, 
                                    config.secrets.session, 
                                    { expiresIn: 60*60*3,algorithm: 'HS256' });
                                    
                                return res.json({
                                    status:'success',
                                    data:{
                                        two_fa_enable:true,
                                        token:token,
                                        role:userfound.role,
                                        id:userfound._id
                                    },msg:'Waiting for 2FA'});
                            }
                        }
                    }
                });
            }
        }
        else
            return res.json({status:'failure',data:[],msg:'Invalid Email !!'});
    });
}
                                                    /**
                                                        * Enable SMS Auth or Change Contact_No
                                                    **/
exports.enableSmsAuth = (req, res)=>
{
    if(!req.body.contact_no || req.body.contact_no == '')
        return res.json({status:'failure', data:[], msg:'Please provide contact no'});
    User.updateOne({_id:req.user._id},{$set:{ contact_no: req.body.contact_no, contact_verify_enable: true}}, (error, status)=>
    {
        if (error)
            return handleError(res, error);
        if (status.nModified)
            return res.json({status:'success', data:[], msg:'SMS Auth Enabled Sucessfully !!!'});
        else
            return res.json({status:'success', data:[], msg:'SMS Auth Already Enabled !!!'});
    });
}
                                                    /**
                                                        * Send SMS Authentication
                                                    **/
exports.sendSmsAuth = (req, res)=>
{
    if(req.user.contact_no)
    {
        let smsCode = Math.floor(1000 + Math.random() * 9000);
        client.messages
        .create(
        {
            body: `Your Stable verification code is : ${smsCode}`,
            from: config.twillio.from,
            to: req.user.contact_no
        })
        .then(message => console.log(`\nMessage ID = ${message.sid}\nTo = ${userfound.contact_no}\nCode = ${smsCode}\n`));

        User.updateOne({_id:req.user._id},{$set:{ contact_verify_key: smsCode}}, (error, status)=>
        {
            if (error)
                return handleError(res, error);
            if (status.nModified)
                return res.json({status: 'success', data:[], msg: `Message Sent Successfully to ${req.user.contact_no}`});
            else
                return res.json({status:'failure', data:[], msg:'Something went wrong !!!'});
        });
    }
    else
        return res.json({status: 'failure', data:[], msg: `Unable to find contact number !!!`});
}
                                                    /**
                                                        * Verify SMS Authentication
                                                    **/
exports.verifySmsAuth = (req, res)=>
{
    if (!req.body.sms_code || req.body.sms_code == '')
        return res.json({status:'failure',data:[],msg:'Please provide SMS Code'});
    User.updateOne({_id:req.user._id, contact_verify_enable:true, contact_verify_key: req.body.sms_code},{$unset:{ contact_verify_key: 1}}, (error, status)=>
    {
        if (error)
            return handleError(res, er1);
        else if (status.nModified)
            return res.json({status: 'success', data:[], msg: `Verified Succesfully !!!`});
        else
            return res.json({status:'failure', data:[], msg:'Invalid Code !!!'});
    });
}
                                                    /**
                                                        * Disable SMS Authentication
                                                    **/
exports.disableSmsAuth = (req, res)=>
{
    User.updateOne({_id:req.user._id},{$set:{ contact_verify_enable: false}, $unset:{ contact_verify_key: 1 }}, (error, status)=>
    {
        if (error)
            return handleError(res, er1);
        if (status.nModified)
            return res.json({status: 'success', data:[], msg: `SMS Auth Disabled Succesfully !!!`});
        else
            return res.json({status:'failure', data:[], msg:'SMS Auth Already Disabled !!!'});
    });
}
                                                    /**
                                                        * Resend Verification Email
                                                    **/
exports.resendVerification = (req, res)=>
{
    if (!req.body.email || req.body.email == '')
        return res.json({status:'failure',data:[],msg:'Please provide email address'});
    
    User.findOne({email:req.body.email}, (er1,userFound)=>
    {
        if (er1) return handleError(res, er1);
        if (userFound) 
        {
            if (!userFound.email_verified)
            {
                let randcode = "";
                let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                for (var i = 0; i < 15; i++)
                    randcode += possible.charAt(Math.floor(Math.random() * possible.length));

                const act_code = randcode+randcode;
                User.updateOne({_id:userFound._id},{$set:{email_verify_key:act_code}},(err,status)=>
                {
                    if (err) return handleError(res, err);
                    if (status.nModified)
                    {
                        // const activation_link = config.clientdomain+'/common/verify_email/'+act_code;
                        const activation_link = config.thisdomain + '/api/users/act/'+ act_code;
                        const templatePath = "server/mail_templates/email_verification.html";
                        let templateContent = fs.readFileSync(templatePath, "utf8");
                        templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
                        templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
                        templateContent = templateContent.replace("##USERNAME##", userFound.name);
                        templateContent = templateContent.replace("##ACTIVATION_LINK##", activation_link);
                        templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);

                        const data = {
                            from: config.mail_from_email,
                            to: userFound.email,
                            subject: config.project_name + ' - Email verification',
                            html: templateContent
                        }

                        config.mailTransporter.sendMail(data, (error, info) =>
                        {
                            if (error)
                                console.log(error);
                            else
                                console.log('Email sent:', info.envelope);
                        });
                        return res.json({status:'success',data:[],msg:'An email was sent to you.'})
                    }
                })
            }
            else
                return res.json({status:'failure',data:[],msg:'Account have already got verified.'});
        }
        else
            return res.json({status:'failure',data:[],msg:'Invalid email provided or Already got verified.'});
    })
}
                                                    /**
                                                        * Update user profile
                                                    **/
exports.updateProfile = (req, res)=>
{
    var allowedKeys = ['avatar','name','auth_pin','language','theme','timezone'];
    var updateObj = {};
    var isUpdate = false;
    allowedKeys.forEach( al_key=>
    {
        if (req.body[al_key])
        {
            isUpdate = true;
            updateObj[al_key] = req.body[al_key];
        }
    });
    if (isUpdate)
    {
        if (req.user.auth_pin)
            delete updateObj.auth_pin;

        User.updateOne({_id: req.user._id},{$set:updateObj}, (err,status)=>
        {
            if (err)
                return handleError(res, err);
            if (status.nModified)
                return res.json({status:'success',data:[],msg:'Updated Successfully'});
            else
                return res.json({status:'failure',data:[],msg:'No records updated'});
            
        })
    }
    else
        return res.json({status:'failure',data:[],msg:'Something went wrong. Please try again.'});
}
                                                    /**
                                                        * Reset Password
                                                    **/
exports.forgotPassword = (req, res)=>
{
    if (!req.body.email || req.body.email == '')
        return res.json({status:'failure',data:[],msg:'Please provide your Email !!!'});

    User.findOne({email:req.body.email}, (err, userfound)=>
    {
        if (err)
            return handleError(res, err);

        if (userfound)
        {
            let randcode = "";
            let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (var i = 0; i < 15; i++)
                randcode += possible.charAt(Math.floor(Math.random() * possible.length));

            const act_code = randcode+userfound._id;

            User.updateOne({_id:userfound._id},{$set:{temp_password:act_code}},function(err1,status)
            {
                if (err1)
                    return handleError(res, err1);
                
                if (status.nModified)
                {
                    const reset_link = config.clientdomain+'/reset_password/'+act_code;
                    const templatePath = "server/mail_templates/forgot_password.html";
                    let templateContent = fs.readFileSync(templatePath, "utf8");
                    templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
                    templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
                    templateContent = templateContent.replace("##USERNAME##", userfound.name);
                    templateContent = templateContent.replace("##USERMAIL##", userfound.email);
                    templateContent = templateContent.replace("##REQ_TIME##", new Date());
                    templateContent = templateContent.replace("##RESET_LINK##", reset_link);
                    templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);
                    
                    const data = {
                        from: config.mail_from_email,
                        to: userfound.email,
                        subject: config.project_name + ' - Reset your password',
                        html: templateContent
                    }

                    config.mailTransporter.sendMail(data, (error, info) =>
                    {
                        if (error)
                            console.log(error);
                        else
                            console.log('Email sent:', info.envelope);
                    });
                    return res.json({status:'success',data:[],msg:`Please check your Email !!!`});
                }
                else
                    return res.json({status:'failure',data:[],msg:'Something went wrong'});
            })
        }
        else
            return res.json({status:'failure',data:[],msg:'Invalid email provided'});
    });
}
                                                    /**
                                                        * Validating IP 
                                                    **/
exports.verifyIP = (req, res)=>
{
    if (!req.params.ip || req.params.ip == '')
        return res.json({status:'failure',data:[],msg:'Invalid request'});

    User.findOne({ip_verify_key:req.params.ip},(err,userfound)=>
    {
        if (err)
            return handleError(res, err);
        if (userfound)
        {
            User.updateOne({_id:userfound._id},{$unset:{ip_verify_key:1}}, (error1, updatedUser)=>
            {
                if(error1)
                    return handleError(res, err);
                else if (updatedUser)
                {
                    const log = new Logging({
                        user_id : userfound._id,
                        ip_address : req.clientIp,
                        user_agent : req.headers['user-agent'],
                        access_time : new Date(),
                        request_url : req.originalUrl,
                    });
                    log.save((error2, saved)=>
                    {
                        if(error2)
                            return handleError(res, err);
                        return res.json({status:'success',data:[],msg:'Device Verified you can Login Now !!!'});
                    });
                }
                else
                    return res.json({status:'failure',data:[],msg:'This link has expired !!!'});
            });
        }
        else
            return res.json({status:'failure',data:[],msg:'This link has expired !!!'});
    });
}
                                                    /**
                                                        * Validating Key 
                                                    **/
exports.validateKey = (req, res)=>
{
    if (!req.params.tempPass || req.params.tempPass == '')
        return res.json({status:'failure',data:[],msg:'Invalid request'});
    
    User.findOne({temp_password:req.params.tempPass},(err,userfound)=>
    {
        if (err)
            return handleError(res, err);
        
        if (!userfound)
            return res.json({status:'failure',data:[],msg:'This link has expired !!!'});
        return res.json({status:'success',data:[],msg:'valid'});
    });
}
                                                    /**
                                                        * Setup New Password
                                                    **/
exports.setPassword = (req, res)=>
{
    if (!req.body.key || req.body.key == '')
        return res.json({status:'failure',data:[],msg:'Invalid request. Please try again'});
    if (!req.body.password || req.body.password == '')
        return res.json({status:'failure',data:[],msg:'Please provide password'})

    User.findOne({temp_password:req.body.key}, (err, user) =>
    {
        if (user)
        {
            user.password = req.body.password;
            user.temp_password = '';
            user.save((err,saved)=>
            {
                if (err)
                    return handleError(res, err) 
                if (saved)
                    return res.json({status:'success',data:[],msg:'Password updated Successfully'});
                else
                    return res.json({status:'failure',data:[],msg:'Unable to process your request. Please try again'});
            });
        }
        else
            return res.json({status:'failure',data:[],msg:'Invalid request, The link might have expired. Please try again.'});
    });
}
                                                    /**
                                                        * Enable 2-FA Auth using SpeakEasy
                                                    **/
exports.enable2Factor = (req, res) =>
{
    if (req.user.two_fa_enable)
        return res.json({status:'failure',data:[],msg:`2-FA Already Activated !!!`});
    
    if (req.user.two_fa_authurl) 
    {
        QRCode.toDataURL(req.user.two_fa_authurl, (err, image_data) =>
        {
                                                // Generate Backup Codes
            let codesArray = [];
            if (req.user.backup_codes && req.user.backup_codes.length > 0)
                codesArray = req.user.backup_codes;
            else
            {
                let i = 0;
                function generate_code()
                {
                    let randcode = "";
                    let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    for (let i = 0; i < 15; i++)
                        randcode += possible.charAt(Math.floor(Math.random() * possible.length));
                    return randcode;
                }
                while(i<5)
                {
                    codesArray.push(generate_code());
                    i++;
                }
                User.updateOne({_id:req.user._id},{$set:{backup_codes:codesArray}}).exec();
            }
            return res.json({status:'success',data:{qr_code_data:image_data,secret:req.user.two_fa_secret_key,backup_codes:codesArray},msg:'QR code for enabling 2 factor authentication'}); // A data URI for the QR code image
        });
    }
    else
    {
                                            // Generate a secret key

        let secret = speakeasy.generateSecret({length: 20});
                                    
                                    // Save this value to your DB for the user

        const user_secret = secret.base32;
        const otpauth_url = secret.otpauth_url.replace('SecretKey',req.user.email)+'&issuer='+config.project_name;

                                            // Generate Backup Codes
        let codesArray = [];
        let i = 0;
        function generate_code()
        {
            let randcode = "";
            let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            for (let i = 0; i < 15; i++)
                randcode += possible.charAt(Math.floor(Math.random() * possible.length));
            return randcode;
        }
        while(i<5)
        {
            codesArray.push(generate_code());
            i++;
        }
        User.updateOne({_id: req.user._id},{$set:{two_fa_secret_key:user_secret,two_fa_authurl:otpauth_url,backup_codes:codesArray}}, (err, saved)=>
        {    
            if (err)
                return handleError(res, err);
            
            if (saved.nModified)
            {
                QRCode.toDataURL(otpauth_url, (err, image_data)=>
                {
                    return res.json({status:'success',data:{qr_code_data:image_data,secret:user_secret,backup_codes:codesArray},msg:'QR code for enabling 2 factor authentication.'}); // A data URI for the QR code image
                });
            }
            else
                return res.json({status:'failure',data:[],msg:'Something went wrong. Please try again'});
        })
    }  
}
                                                    /**
                                                        * Verify 2-FA Auth using Token
                                                    **/
exports.verify2Factor = (req, res)=>
{
    if (!req.body.token_code || req.body.token_code == '')
        return res.json({status:'failure',data:[],msg:'Please provide code to verify'});

    User.findOne({_id:req.user._id},{},(err, userfound)=>
    {
        if (err)
            return handleError(res, err);
        
        if (userfound)
        {
            if (userfound.two_fa_secret_key)
            {
                let verified = speakeasy.totp.verify({ secret: userfound.two_fa_secret_key, encoding: 'base32', token: req.body.token_code });
                if (verified)
                {
                    loginNotification(req, userfound, res, (cbData)=>
                    {
                        User.updateOne({_id:req.user._id,two_fa_enable:false},{$set:{two_fa_enable:true}}).exec();
                        return res.json({status:'success',data:{token:cbData.token,first_login:cbData.is_first_login,referral_code:cbData.ref_code},msg:'Sucessfully Authenticated !!!'});
                    })
                }
                else
                   return res.json({status:'failure',data:verified,msg:'Invalid code'});
            }
            else
                return res.json({status:'failure',data:[],msg:'Please set up two factor authentication'});
        }
        else
            return res.json({status:'failure',data:[],msg:'Something went wrong. Please try again'});
    });
}
                                                    /**
                                                        * Disable 2-FA Auth
                                                    **/
exports.disable2Factor = (req, res) =>
{
    User.updateOne({_id:req.user._id},{$set:{two_fa_enable:false},$unset:{two_fa_authurl:1,two_fa_secret_key:1,backup_codes:1}}).exec((err, status) =>
    {
        if (err)
            return handleError(res, err);

        if (status.nModified)
            return res.json({status:'success',data:[],msg:'Disabled 2 Factor authentication'});
        else
            return res.json({status:'failure',data:[],msg:'Something went wrong. Please try again'});
    });
}
                                                    /**
                                                        * Update Tracking Status
                                                    **/
exports.updateTracking = (req, res) =>
{
    let updateObj = {};
    if (req.params.status == 0)
        updateObj.can_track = false;
    else if(req.params.status == 1)
        updateObj.can_track = true;
    else
        return res.json({status:'failure',data:[],msg:'Something went wrong Please try again'});

    User.updateOne({_id:req.user._id},{$set:updateObj},(err, updated) =>
    {
        if (err)
            return handleError(res, err);

        if (updated.nModified)
            return res.json({status:'success',data:[],msg:'Updated successfully'});
        else
            return res.json({status:'failure',data:[],msg:'Unable to update now. Please try again'});
    });
}
                                                    /**
                                                        * Get KYC Info
                                                    **/
exports.getKycInfo = function(req, res)
{
    const kyc = req.user.kyc ? req.user.kyc : {};
    if (req.user.is_kyc_verified === 'Verified')
        return res.json({status:'success',data:{kyc:kyc,is_kyc_verified:req.user.is_kyc_verified,kyc_created_at:req.user.kyc_created_at,kyc_updated_at:req.user.kyc_updated_at,kyc_comment:req.user.kyc_comment},msg:'Your KYC is verified'});
    else
        return res.json({status:'success',data:{kyc:kyc,is_kyc_verified:req.user.is_kyc_verified},msg:'Please check and update your information to get your KYC verified'});
}
                                                    /**
                                                        * Save user KYC
                                                    **/
exports.saveKyc = function(req, res)
{
  if (req.files !== null)
  {
    for (let s_file in req.files)
    {
      uploadingimages(req, s_file, function(filename)
      {
        req.body[s_file] = filename;
      });
    }
  }
  setTimeout(updateNow,500);
  
  function updateNow()
  {
    let user_kyc = req.user.kyc ? req.user.kyc : {};
    let updatedObj = {};
    
    updatedObj['kyc'] = _.merge(user_kyc,req.body);
    updatedObj['is_kyc_verified'] = 'Pending';
    updatedObj['kyc_updated_at'] = new Date();
    
    if (!req.user.kyc)
        updatedObj['kyc_created_at'] = new Date();
    
    User.updateOne({_id:req.user._id,is_kyc_verified:{$ne:'Verified'}},{$set:updatedObj},function(err,updated)
    {
        if (err)
            return handleError(res, err);
        if (updated.nModified)
            return res.json({status:'success',data:req.body,msg:'Updated successfully. Pending for verification'});
        else
        {
            const kyc = req.user.kyc ? req.user.kyc : req.body;
            return res.json({status:'failure',data:kyc,msg:'Nothing to update.'});
        }
    });
  }
}
                                                    /**
                                                        * Verify Backup Code
                                                    **/
exports.verify_backup_code = (req, res)=>
{
    if (!req.body.key)
        return res.json({status:'failure',data:[],msg:'Please provide one of your backup codes'});

    if (req.user.backup_codes && req.user.backup_codes.length > 0) 
    {
        let codes = req.user.backup_codes;
        const code_index = codes.indexOf(`${req.body.key}`);
        if (code_index >= 0)
        {
            codes.splice(code_index,1);
            User.updateOne({_id:req.user._id},{$set:{backup_codes:codes}}).exec();
            return res.json({status:'success',data:codes,msg:'successfully verified'});
        }
        else
            return res.json({status:'failure',data:[],msg:'Invlaid key'});
    }
    else
        return res.json({status:'failure',data:[],msg:'No backup codes found'});
}
                                                    /**
                                                        * User whom submitted KYC
                                                    **/
exports.getKycUsers = (req, res)=>
{
    let userCntQry = User.count({role:'user',kyc:{$exists:true}});
    let userQry = User.find({role:'user',kyc:{$exists:true}},{name:1,role:1,email:1,email_verified:1,is_kyc_verified:1,kyc:1,kyc_created_at:1,kyc_updated_at:1,kyc_comment:1,created_at:1}).lean();
    
    if (req.body.verified) 
    {
        userCntQry._conditions['is_kyc_verified'] = req.body.verified;
        userQry._conditions['is_kyc_verified'] = req.body.verified;
    }
    if (req.body._id)
    {
        userCntQry._conditions['_id'] = req.body._id;
        userQry._conditions['_id'] = req.body._id;
    }
    if (req.body.search_key)
    {
        userCntQry._conditions['email'] = new RegExp(req.body.search_key,'i');
        userQry._conditions['email'] = new RegExp(req.body.search_key,'i');
    }

    let resultLimit = req.body.limit ? parseInt(req.body.limit) : 50;

    if (req.body.skip) 
    {
        const skipVal = parseInt(req.body.skip);
        userQry.options['skip'] = skipVal;
        userQry.options['limit'] = resultLimit;
    }
    
    userCntQry.exec(function(er1,usersCount)
    {
        userQry.exec(function(er2,usersList)
        {
            return res.json({status:'success',data:usersList,total:usersCount,msg:'Users list'});
        });
    });
}
                                                    /**
                                                        * Update KYC by ADMIN
                                                    **/
exports.kycStatus = (req, res)=>
{
    if (!req.body.user_id || req.body.user_id == '')
        return res.json({status:'failure',data:[],msg:'Please provide user id'});
    
    if (!req.body.status || req.body.status == '')
        return res.json({status:'failure',data:[],msg:'Please provide status'});
    
    User.findOne({_id:req.body.user_id},{email:1,name:1}, (er2,userFound)=>
    {
        User.updateOne({_id:req.body.user_id},{$set:{is_kyc_verified:req.body.status,kyc_comment:req.body.kyc_comment}}, (er1, updated)=>
        {
        if (er1)
            return handleError(res, er1);

        if (updated.nModified) 
        {
            let templatePath = "server/mail_templates/kyc.html";
            let templateContent = fs.readFileSync(templatePath, "utf8");
            templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
            templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
            templateContent = templateContent.replace("##USERNAME##", userFound.name);
            templateContent = templateContent.replace("##KYC_STATUS##", req.body.status);
            templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);

            let data = {
                from: config.mail_from_email,
                to: userFound.email,
                subject: config.project_name + ' - KYC',
                html: templateContent
            }

            config.mailTransporter.sendMail(data, (error, info) =>
            {
                if (error) 
                    console.log(error);
                else
                    console.log('Email sent:', info.envelope);
            });
            return res.json({status:'success',data:[],msg:'Updated successfully'});
        }
        else
            return res.json({status:'failure',data:[],msg:'Nothing was updated. Please try again'});
        });
    });
}
                                                    /**
                                                        * Get Referral Cron
                                                    **/
exports.referralCron = (req, res)=>
{
  multilevelReference((respData)=>
  {
    return res.json(respData);
  });
}
                                                    /**
                                                        * Get multilevel referral statistics
                                                    **/
exports.referralStats = (req, res)=>
{
    Referral.find({}).populate({path:'user_id', select:'_id name email'}).lean().exec((er1,refStats)=>
    {
        if (er1) return handleError(res, er1);
        return res.json({status:'success',data:refStats,msg:'Multi level referral statistics'});
    });
}
                                                    /**
                                                        * Get Reference Users
                                                    **/
exports.myReferences = (req, res)=>
{
    if (req.user.is_affiliate) 
    {
        User.find({referred_by:req.user.referral_code},{name:1,email:1,email_verified:1,is_kyc_verified:1,is_airdrop:1,created_at:1}).lean().exec((er1, refList)=>
        {
            if (er1) { return handleError(res, er1); }
            return res.json({status:'success',data:refList,msg:'Referred users list'});
        });
    }
    else
        return res.json({status:'failure',data:[],msg:'Unauthorized to view report'});
}
                                                    /**
                                                        * Validate Username
                                                    **/
exports.validateUname = (req, res)=>
{
    if (!req.body.uname || req.body.uname == '')
        return res.json({status:'failure',data:[],msg:'Please provide user name'});

    const uname = req.body.uname.toLowerCase();

    User.findOne({uname:uname},{uname:1},(er1, uFound)=>
    {
        if (er1)
            return handleError(res, er1);
        if (uFound)
            return res.json({status:'failure',data:[],msg:`${req.body.uname} already exists.`});
        else
            return res.json({status:'success',data:[],msg:'Available'});
    })
}
                                                    /**
                                                        * Search Users
                                                    **/
exports.search = (req, res)=>
{
    if (!req.body.uname || req.body.uname == '')
        return res.json({status:'failure',data:[],msg:'Please provide user name to search'});

    const uname = req.body.uname.toLowerCase();
    User.findOne({uname:uname},{uname:1},(er1, uFound)=>
    {
        if (er1)
            return handleError(res, er1);
        if (uFound)
            return res.json({status:'success',data:[],msg:`${req.body.uname} exists.`});
        else
            return res.json({status:'failure',data:[],msg:'User not found'});
    });
}
                                                    /**
                                                        * GET list of Users
                                                    **/
exports.listUsers = function(req, res)
{
    let userQry = User.count({role:{$ne:'admin'}});
    let balQry = User.find({role:{$ne:'admin'}}, 
        { 
        "name":1,  
        "email":1, 
        "role":1,
        "avatar":1,
        "referral_count":1,
        "kyc":1,
        "email_verified":1,
        "created_at":1,
        "is_kyc_verified":1,
        "is_affiliate":1,
        "is_airdrop":1,
        "balance":1,
        "twitter_username":1,
        "telegram_username":1
        });
    if (req.body.role == 'airdrop')
    {
        userQry._conditions['is_airdrop'] = true;
        balQry._conditions['is_airdrop'] = true;
    }
    if (req.body.role == 'affiliateAdmin')
    {
        userQry._conditions['role'] = 'affiliateAdmin';
        balQry._conditions['role'] = 'affiliateAdmin';
    }
    if (req.body.search_key)
    {
        userQry._conditions['email'] = new RegExp(req.body.search_key,'i');
        balQry._conditions['email'] = new RegExp(req.body.search_key,'i');
    }
    if (req.body.role == 'email_verified')
    {
        userQry._conditions['email_verified'] = true;
        balQry._conditions['email_verified'] = true;
    }
    if (req.body._id) {
        userQry._conditions['_id'] = req.body._id;
        balQry._conditions['_id'] = req.body._id;
    }
    let resultLimit = req.body.limit ? parseInt(req.body.limit) : 50;

    if (req.body.skip)
    {
        const skipVal = parseInt(req.body.skip);
        balQry.options['skip'] = skipVal;
        balQry.options['limit'] = resultLimit;
    }
    
    userQry.exec(function(er1,usersCount)
    {
        balQry.exec(function(er2,userResp)
        {
            return res.json({status:'success',total:usersCount,data:userResp,msg:'Users list'});
        });
    })
}
                                                    /**
                                                        * Dashboard Statistics
                                                    **/
exports.stats = function(req, res)
{
    let today = new Date();
    let now = new Date();

    let td = new Date();
    td.setDate(td.getDate() - 30);
    let lastDay = td.toJSON().slice(0,10);

    let currentDay = now.toJSON().slice(0,10);
    let finalData = {
        total_users:0,
        email_verified:0,
        kyc_pending:0,
        kyc_verified:0,
        orders_data:[],
        withdrawal_requests:[]
    };
                                                                //Email Query

    let emailStatsQry = User.aggregate([{ $match:{ role:'user' }},{ $group:{ _id: { email_verified:"$email_verified" }, count:{ $sum:1 }}}])
                            .allowDiskUse(true)
                            .cursor({ batchSize: 50000 });
                                                                
                                                                // KYC Query

    let kycStatsQry  =  User.aggregate([{ $match:{ role:'user' }},{ $group:{ _id: { is_kyc_verified:"$is_kyc_verified"}, count:{ $sum:1 }}}])
                            .allowDiskUse(true)
                            .cursor({ batchSize: 50000 });
                                                        
                                                                // Execution
    let emailStats = emailStatsQry.exec();
    let kycStats = kycStatsQry.exec();
                                                            // Response processing
    emailStats.map(doc=>
    {
                                                            // DOC manupulation
        return doc;
    })
    .on('data',usr=>
    {
        if (usr._id.email_verified == true) 
            finalData.email_verified = usr.count;
        finalData.total_users = finalData.total_users + usr.count;
    })
    .on('end',noData=>
    {
        kycStats.map(kycDoc=>
        {
                                                            // KYCDoc manupulation
            return kycDoc;
        })
        .on('data',kycData=>
        {
            if (kycData._id.is_kyc_verified == 'Pending') 
                finalData.kyc_pending = kycData.count;
            if (kycData._id.is_kyc_verified == 'Verified')
                finalData.kyc_verified = kycData.count;
        })
        .on('end',noData=>
        {
            return res.json({status:'success',data:finalData,msg:'Dashboard data'});
        });
    });
}
                                                    /**
                                                        * Test Email
                                                    **/
exports.testMail = function(req, res)
{
    if (!req.body.email || req.body.email == '') 
        return res.json({status:'faulure',data:'Please provide email'});

    let templatePath = "server/mail_templates/sample.html";
    let templateContent = fs.readFileSync(templatePath, "utf8");
    templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
    templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
    templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);

    let data = {
        from: config.mail_from_email,
        to: req.body.email,
        subject: config.project_name + ' - Testing',
        html: templateContent
    }

    config.mailTransporter.sendMail(data, (error, info) =>
    {
        if (error)
            return res.json('Unable to send email !!!');
        else
            console.log('Email sent:', info.envelope);
        return res.json("Mail sent");
    });
}
                                                    /**
                                                        * Authentication callback
                                                    **/
exports.authCallback = function(req, res, next)
{
  res.redirect('/');
};
                                                    /**
                                                        * Update user in DB and send email
                                                    **/
function loginNotification(req, userfound, res, next)
{
    const templatePath = "server/mail_templates/sign_in.html";
    let templateContent = fs.readFileSync(templatePath, "utf8");
    templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
    templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
    templateContent = templateContent.replace("##USERNAME##", userfound.name);
    templateContent = templateContent.replace("##REQ_TIME##", new Date());
    templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);
    const data = {
        from: config.mail_from_email,
        to: userfound.email,
        subject: config.project_name + ' - Account Sign In',
        html: templateContent
    }
    config.mailTransporter.sendMail(data, (error, info) => 
    {
        if (error)
            console.log(error);
        else
            console.log('Email sent:', info.envelope);
    });

    function rand_code()
    {
        let randcode = "";
        let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (let i = 0; i < 6; i++)
            randcode += possible.charAt(Math.floor(Math.random() * possible.length));
        return randcode+`${userfound._id}`.substring(10,15);
    }

    const is_first_login = userfound.last_login ? false : true;
    const ref_code = (userfound.referral_code && userfound.email_verified === true) ? userfound.referral_code : rand_code();
    let token = jwt.sign({_id: userfound._id }, config.secrets.session, { expiresIn: 60*60*3,algorithm: 'HS256' });
    
    logging.newlog(req,userfound._id);

    const date_now = new Date();
    User.updateOne({_id: userfound._id},{$set:{last_login:date_now,last_login_from:req._remoteAddress,referral_code:ref_code}}).exec();
    
    next({token:token,first_login:is_first_login,referral_code:ref_code});
}
                                                    /**
                                                        * Update user in DB and send email
                                                    **/
function configureIpNotification(req, user, next)
{
    let randcode = "";
    let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < 5; i++)
        randcode += possible.charAt(Math.floor(Math.random() * possible.length));

    const act_code = randcode+randcode;
    const date_now = new Date();
    User.updateOne({_id:user._id}, {$set:{ip_verify_key:act_code,updated_by:user._id,updated_at:date_now}},(error, status)=>
    {
        if(error)
            next(false);
        else if(status.nModified)
        {
            let activation_link = config.clientdomain + '/verify_ip/' + act_code;
            const templatePath = "server/mail_templates/sign_up.html";
            let templateContent = fs.readFileSync(templatePath, "utf8");
            templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
            templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
            templateContent = templateContent.replace("##USERNAME##", user.name);
            templateContent = templateContent.replace("##ACTIVATION_LINK##", activation_link);
            templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);
        
            const data =
            {
                from: config.mail_from_email,
                to: user.email,
                subject: config.project_name + ' - Sign up',
                html: templateContent
            }
        
            config.mailTransporter.sendMail(data, (error, info) =>
            {
                if (error)
                    next(false)
                else
                {
                    next(true)
                    console.log('Email sent:', info.envelope);
                }
            });
        }
        else next(false)
    });
}
                                                    /**
                                                        * Uploading Files
                                                    **/
function uploadingimages(req, req_file, callback)
{
    let sampleFile = req.files[req_file];
    let filename = sampleFile.name;
    let rendomkeys = "QWERTYUIOPLKJHGFDSAZXCVBNMabcdefghijklmnopqrstuvwxyz0123456789";
    let randomname = "";
    for (let i = 0; i < 10; i++)
        randomname += rendomkeys.charAt(Math.floor(Math.random() * rendomkeys.length));

    let finalname = randomname + filename;
    sampleFile.mv(config.root+'/uploads/' + finalname, (err) =>
    { 
        let path = finalname;
        if (err)
        { 
            console.log(err);
            callback(''); 
        }
        else callback(path);
    });
}
                                                    /**
                                                        * Update Multi level Referencing
                                                    **/
function multilevelReference(cb)
{
    User.find({role:'user',referral_code:{$exists:true}},{_id:1,name:1,referral_code:1,referred_by:1}).lean().exec((er1, allUsers)=>
    {
        if (er1) return handleError(res, er1);
        function updateReferences(re)
        {
            return new Promise((resolve,reject)=>
            {
                async.forEachOf(allUsers, (val,ke,cb)=>
                {
                    val['l'+re] = [];
                    val['l'+re+'_codes'] = [];
                    for (let i = 0; i < allUsers.length; i++)
                    {
                        if (re == 1)
                        {
                            if (allUsers[i]['referred_by'] && (allUsers[i]['referred_by'] === val['referral_code']))
                            {
                                val['l'+re].push(allUsers[i]['_id']);
                                val['l'+re+'_codes'].push(allUsers[i]['referral_code']);
                            }
                        }
                        else
                        {
                            if (allUsers[i]['referred_by'] && (val['l'+(re-1)+'_codes'].indexOf(allUsers[i]['referred_by']) >= 0))
                            {
                                val['l'+re].push(allUsers[i]['_id']);
                                val['l'+re+'_codes'].push(allUsers[i]['referral_code']);
                            }
                        }
                    }
                    setTimeout(cb, 1000);
                },(err)=>
                {
                    resolve(true);
                });
            });
        }
        const iterations = [1];
        let actions = iterations.map(updateReferences);
        let results = Promise.all(actions);
        results.then(data =>
        {
            function updateReferDb(s_user)
            {
                const uid = s_user['_id'];
                delete s_user['_id'];
                let query = { 'user_id': uid };
                Referral.findOneAndUpdate(query, s_user, { upsert: true }, (err, doc)=>
                {
                    if (err) console.log('failed to update referencess');
                    return new Promise((resolve,reject)=>
                    {
                        resolve(true);
                    });
                }); 
            }
            let dbActions = allUsers.map(updateReferDb);
            let dbResults = Promise.all(dbActions);

            dbResults.then(dbResp=>
            {
                console.log('multilevel reference updation completed');
                if (cb)
                {
                    cb(allUsers);
                }
            });
        });
    })
}

const validationError = (res, err) =>
{
    return res.status(422).json({status:'failure',data:err,msg:'Something went wrong'});
};

function handleError(res, err)
{
    return res.status(500).send({status:'failure',data:err,msg:'Something went wrong'});
}