'use strict';

const fs = require('fs');
const _ = require('lodash');
const async = require('async');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const speakeasy = require("speakeasy");

const User = require('./user.model');
const config = require('../../config/environment');
const Logging = require('../logging/logging.model');
const logging = require('../logging/logging.controller');
const client = require('twilio')(config.twillio.accountSid, config.twillio.authToken);

                                                    /**
                                                        * Creates a new user
                                                    **/
exports.create = (req, res) =>
{
    if (!req.body.name || req.body.name == '')
        return res.json({status: false,data:[],msg:'Please provide name'});
    if (!req.body.email || req.body.email == '')
        return res.json({status: false,data:[],msg:'Please provide email id'});
    if (!req.body.password || req.body.password == '')
        return res.json({status: false,data:[],msg:'Please provide password for your account'});
    if (!req.body.terms_cond || req.body.terms_cond == '')
        return res.json({status: false,data:[],msg:'Please agree to terms and conditions to proceed'});
    if (validator.isEmail(req.body.email) === false) 
        return res.json({status: false,data:[],msg:'Please provide valid email id'});
    if (!req.body.uname || req.body.uname == '')
        return res.json({status: false,data:[],msg:'Please provide username !!!'});
    
    const uname = req.body.uname.toLowerCase();
    const umail = req.body.email.toLowerCase();
    User.findOne({$or:[{email:umail},{uname: uname}]}, (err,userfound) =>
    {
        if (err) return handleError(res, err);
        if (userfound) 
            if (userfound.email == umail)
                return res.json({status: false,data:[],msg:"Email is already used !!!"});
            else return res.json({status: false,data:[],msg:"Username is already used !!!"});
        else
        {
            let randcode = "";
            let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (let i = 0; i < 15; i++) randcode += possible.charAt(Math.floor(Math.random() * possible.length));

            let newUser = 
            {
                email: umail,
                uname: uname,
                name: req.body.name,
                emailVerifyKey: randcode,
                password: req.body.password,
                isTermAccepted: req.body.terms_cond
            }
            newUser = new User(newUser);
            newUser.save((error, user)=>
            {
                if (error) return validationError(res, error);

                const activationLink = `${config.thisdomain}/api/users/verifyEmail/${randcode}`;

                const templatePath = "mail_templates/sign_up.html";
                let templateContent = fs.readFileSync(templatePath, "utf8");
                templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
                templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
                templateContent = templateContent.replace("##USERNAME##", user.name);
                templateContent = templateContent.replace("##ACTIVATION_LINK##", activationLink);
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
                return res.json({ status: true,data:{token: token },msg:'Registered successfully. Please confirm your Email !!'});
            });
        }
    })
};
                                                    /**
                                                        * Login User
                                                    **/
exports.authenticate = (req, res) =>
{
    if (!req.body.email || req.body.email == '')
        return res.json({status: false,data:[],msg:'Enter Email to Login !!'});
    if (!req.body.password || req.body.password == '')
        return res.json({status: false,data:[],msg:'Enter Password to Login !!'});
    
    User.findOne({email:req.body.email},{source:0},(err,userfound)=>
    {
        if (err) return handleError(res, err);
        if (userfound)
        {
            if (!userfound.authenticate(req.body.password))
                return res.json({status: false,data:[],msg:'Invalid Password !!'});
            else if(!userfound.emailVerified)
                return res.json({status: false,data:[],msg:'Please verify your email address to proceed.'});
            else
            {
                Logging.find({userId: userfound._id, ipAddress: process.env.IP}).exec((error, login)=>
                {
                    if(error) 
                        return handleError(res, error);
                    else if(login.length === 0)
                        configureIpNotification(req, userfound, (data)=>
                        {
                            return res.json({status: false, data:[], msg:'Please Verify your Device by email !!!'});
                        });
                    else if (!userfound.twoFaEnabled)
                        loginNotification(req, userfound, res, (cbData)=>
                        {
                            return res.json({
                                status: true,
                                data:{
                                    token: cbData.token,
                                    id: userfound._id,
                                    twoFaEnabled: false,
                                    role: userfound.role
                                },msg:'Login Sucessfull !!'});
                        });
                    else
                    {
                        const token = jwt.sign(
                            {_id: userfound._id }, 
                            config.secrets.session, 
                            { expiresIn: 60*60*3,algorithm: 'HS256' });

                        return res.json(
                        {
                            status: true, 
                            data:{ 
                                twoFaEnabled:true, 
                                token:token, 
                                role:userfound.role, 
                                id:userfound._id 
                            },msg:'Waiting for 2FA'
                        });
                    }
                });
            }
        }
        else return res.json({status: false,data:[],msg:'Invalid Email !!'});
    });
}
                                                    /**
                                                        * Activate Account
                                                    **/
exports.verifyEmail = (req, res)=>
{
    if (!req.params.actCode || req.params.actCode == '')
        return res.json({status: false, data:[], msg:'Invalid request. Please try again'})

    User.findOne({emailVerifyKey:req.params.actCode,emailVerified:false},{},(error,userDetails)=>
    {
        if (error) return handleError(res, error);
        else if (userDetails)
        {
            logging.newlog(req,userDetails._id);
            const dateNow = new Date();
            User.updateOne({_id:userDetails._id},{$set:{emailVerified: true, isActive: true, updatedBy: userDetails._id, updatedAt: dateNow}, $unset: {emailVerifyKey: 1}}, (error, status)=>
            {
                if (error) return handleError(res, error);
                if (!status.nModified)
                    return res.json({status: false, data:[], msg: 'Something went wrong. Please try again !!!'});
                return res.json({status: true, data:[], msg: 'Successfully verified your email !!!'});
            })
        }
        else return res.json({status: false, data: [], msg: 'This link got expired !!!'});
    })
}
                                                    /**
                                                        * Validating IP 
                                                    **/
exports.verifyIP = (req, res)=>
{
    if (!req.params.ip || req.params.ip == '')
        return res.json({status: false,data:[],msg:'Invalid request'});
    User.findOne({ipVerifyKey: req.params.ip},(error, userfound)=>
    {
        if (error) return handleError(res, error);
        if (userfound)
        {
            User.updateOne({_id: userfound._id}, {$unset: {ipVerifyKey: 1}}, (error, updatedUser)=>
            {
                if(error) return handleError(res, error);
                else if (updatedUser)
                {
                    const log = new Logging(
                    {
                        accessTime : new Date(),
                        userId : userfound._id,
                        ipAddress : process.env.IP,
                        requestUrl : req.originalUrl,
                        userAgent : req.headers['user-agent']
                    });
                    log.save((error, saved)=>
                    {
                        if(error) return handleError(res, err);
                        return res.json({status: true,data:[],msg:'Device Verified you can Login Now !!!'});
                    });
                }
                else return res.json({status: false,data:[],msg:'This link has expired !!!'});
            });
        }
        else return res.json({status: false,data:[],msg:'This link has expired !!!'});
    });
}
                                                    /**
                                                        * Resend Verification Email
                                                    **/
exports.resendVerification = (req, res)=>
{
    if (!req.body.email || req.body.email == '')
        return res.json({status: false,data:[],msg:'Please provide email address'});
    if (validator.isEmail(req.body.email) === false) 
        return res.json({status: false,data:[],msg:'Please provide valid email address'});

    User.findOne({email:req.body.email}, (error,userFound)=>
    {
        if (error) return handleError(res, error);
        if (userFound)
        {
            if (!userFound.emailVerified)
            {
                let randcode = "";
                let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                for (var i = 0; i < 15; i++)
                    randcode += possible.charAt(Math.floor(Math.random() * possible.length));

                User.updateOne({_id: userFound._id},{$set: {emailVerifyKey: randcode}},(error, status)=>
                {
                    if (error) return handleError(res, error);
                    if (status.nModified)
                    {
                        const activationLink = `${config.thisdomain}/api/users/verifyEmail/${randcode}`;
                        const templatePath = "mail_templates/email_verification.html";
                        let templateContent = fs.readFileSync(templatePath, "utf8");
                        templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
                        templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
                        templateContent = templateContent.replace("##USERNAME##", userFound.name);
                        templateContent = templateContent.replace("##ACTIVATION_LINK##", activationLink);
                        templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);

                        const data = {
                            from: config.mail_from_email,
                            to: userFound.email,
                            subject: config.project_name + ' - Email verification',
                            html: templateContent
                        }

                        config.mailTransporter.sendMail(data, (error, info) =>
                        {
                            if (error) console.log(error);
                            else console.log('Email sent:', info.envelope);
                        });
                        return res.json({status: true,data:[],msg:'Please check your Email.'})
                    }
                })
            }
            else return res.json({status: false,data:[],msg:'Account have already got verified.'});
        }
        else return res.json({status: false,data:[],msg:'Invalid email provided or Already got verified.'});
    })
}
                                                    /**
                                                        * Get my Profile
                                                    **/
exports.myProfile = (req, res, next)=>
{
    const userId = req.user._id;
    User.findOne({ _id: userId }, '-salt -hashedPassword -emailVerifyKey -twoFaKey').lean().exec((error, user)=>
    {
        if (error) return next(error);
        else if (!user)
            return res.status(401).json({status: false,data:[],msg:'User not found'});
        return res.json({status: true,data:user,msg:'Profile details'});
    });
};
                                                    /**
                                                        * Update user profile
                                                    **/
exports.updateProfile = (req, res)=>
{
    let allowedKeys = ['avatar','name','phone','timezone'];
    let updateObj = {};
    let isUpdate = false;
    allowedKeys.forEach( key=>
    {
        if (req.body[key])
        {
            isUpdate = true;
            updateObj[key] = req.body[key];
        }
    });
    if (isUpdate)
    {
        User.updateOne({_id: req.user._id},{$set:updateObj}, (error,status)=>
        {
            if (error) return handleError(res, error);
            if (!status.nModified)
                return res.json({status: false,data:[],msg:'No records updated'});
            return res.json({status: true,data:[],msg:'Updated Successfully'});
        })
    }
    else return res.json({status: false,data:[],msg:'Please Provide Valid Key'});
}
                                                    /**
                                                        * Change a users password
                                                    **/
exports.changePassword = (req, res) =>
{
  const userId = req.user._id;
  const oldPass = String(req.body.oldPassword);
  const newPass = String(req.body.newPassword);

  if (!req.body.oldPassword || !req.body.newPassword || req.body.oldPassword == '' || req.body.newPassword == '')
    return res.json({status: false,data:[],msg:'Please provide password'});

  User.findById(userId, (error, user) =>
  {
    if(user.authenticate(oldPass))
    {
      user.password = newPass;
      user.save((err)=>
      {
        if (err) return validationError(res, err);

        const templatePath = "mail_templates/change_password.html";
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
        return res.json({status: true,data:[],msg:'Password changed Successfully'});
      });
    }
    else
      return res.send({status: false,data:[],msg:'Incorrect current password'});
  });
};
                                                    /**
                                                        * Reset Password
                                                    **/
exports.forgotPassword = (req, res)=>
{
    if (!req.body.email || req.body.email == '')
        return res.json({status: false,data:[],msg:'Please provide your Email !!!'});

    User.findOne({email:req.body.email}, (err, userfound)=>
    {
        if (err) return handleError(res, err);
        if (userfound)
        {
            let randcode = "";
            let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (var i = 0; i < 15; i++)
                randcode += possible.charAt(Math.floor(Math.random() * possible.length));

            User.updateOne({_id:userfound._id},{$set:{tempPassword:randcode}},function(err1,status)
            {
                if (err1) return handleError(res, err1);
                if (status.nModified)
                {
                    const reset_link = `${config.clientdomain}/api/users/passwordKey/${randcode}`;
                    const templatePath = "mail_templates/forgot_password.html";
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
                        if (error) console.log(error);
                        else console.log('Email sent:', info.envelope);
                    });
                    return res.json({status: true,data:[],msg:`Please check your Email !!!`});
                }
                else return res.json({status: false,data:[],msg:'Something went wrong'});
            })
        }
        else return res.json({status: false,data:[],msg:'Invalid email provided'});
    });
}
                                                    /**
                                                        * Validate Password Key 
                                                    **/
exports.passwordKey = (req, res)=>
{
    if (!req.params.tempPass || req.params.tempPass == '')
        return res.json({status: false,data:[],msg:'Invalid request'});
    
    User.findOne({tempPassword:req.params.tempPass},(err,userfound)=>
    {
        if (err) return handleError(res, err);
        if (!userfound)
            return res.json({status: false,data:[],msg:'This link has expired !!!'});
        return res.json({status: true,data:[],msg:'valid'});
    });
}
                                                    /**
                                                        * Setup New Password
                                                    **/
exports.setPassword = (req, res)=>
{
    if (!req.body.key || req.body.key == '')
        return res.json({status: false,data:[],msg:'Invalid request. Please try again'});
    if (!req.body.password || req.body.password == '')
        return res.json({status: false,data:[],msg:'Please provide password'})

    User.findOne({tempPassword:req.body.key}, (err, user) =>
    {
        if (user)
        {
            user.password = req.body.password;
            user.tempPassword = '';
            user.save((err,saved)=>
            {
                if (err) return handleError(res, err) 
                if (!saved) 
                    return res.json({status: false,data:[],msg:'Unable to process your request. Please try again'});
                return res.json({status: true,data:[],msg:'Password updated Successfully'});
            });
        }
        else return res.json({status: false,data:[],msg:'Invalid request, The link might have expired. Please try again.'});
    });
}
                                                    /**
                                                        * Enable SMS Auth or Change phone
                                                    **/
exports.enableSmsAuth = (req, res)=>
{
    let { phone } = req.body;
    if(!phone || phone == '')
        return res.json({status: false, data:[], msg:'Please provide phone no'});
    User.updateOne({_id:req.user._id},{$set:{ phone, smsVerifyEnabled: true}}, (error, status)=>
    {
        if (error) return handleError(res, error);
        if (status.nModified) return res.json({status: true, data:[], msg:'SMS Auth Enabled Sucessfully !!!'});
        return res.json({status: true, data:[], msg:'SMS Auth Already Enabled !!!'});
    });
}
                                                    /**
                                                        * Send SMS Authentication
                                                    **/
exports.sendSmsAuth = (req, res)=>
{
    if(req.user.phone)
    {
        let smsCode = Math.floor(1000 + Math.random() * 9000);
        client.messages.create(
        {
            body: `Your Tokenism verification code : ${smsCode}`,
            from: config.twillio.from,
            to: req.user.phone
        });

        User.updateOne({_id:req.user._id, smsVerifyEnabled: true}, {$set: {smsVerifyKey: smsCode}}, (error, status)=>
        {
            if (error) return handleError(res, error);
            if (status.nModified) 
                return res.json({status: true, data:[], msg: `Message Sent Successfully to ${req.user.phone}`});
            return res.json({status: false, data:[], msg:'Something went wrong !!!'});
        });
    }
    else return res.json({status: true, data:[], msg: `Unable to find contact number !!!`});
}
                                                    /**
                                                        * Verify SMS Authentication
                                                    **/
exports.verifySmsAuth = (req, res)=>
{
    if (!req.body.sms_code || req.body.sms_code == '')
        return res.json({status: false,data:[],msg:'Please provide SMS Code'});
    User.updateOne({_id:req.user._id, smsVerifyEnabled:true, smsVerifyKey: req.body.sms_code},{$unset:{ smsVerifyKey: 1}}, (error, status)=>
    {
        if (error) return handleError(res, er1);
        else if (status.nModified)
            return res.json({status: true, data:[], msg: `Sms Succesfully Verified !!!`});
        return res.json({status: false, data:[], msg:'Invalid Code !!!'});
    });
}
                                                    /**
                                                        * Disable SMS Authentication
                                                    **/
exports.disableSmsAuth = (req, res)=>
{
    User.updateOne({_id:req.user._id, smsVerifyEnabled: true},{$set:{ smsVerifyEnabled: false}, $unset:{ smsVerifyKey: 1 }}, (error, status)=>
    {
        if (error) return handleError(res, er1);
        if (status.nModified)
            return res.json({status: true, data:[], msg: `SMS Auth Disabled Succesfully !!!`});
        return res.json({status: false, data:[], msg:'SMS Auth Already Disabled !!!'});
    });
}
                                                    /**
                                                        * Enable 2-FA Auth using SpeakEasy
                                                    **/
exports.enable2Factor = (req, res) =>
{
    if (req.user.twoFaEnabled)
        return res.json({status: false,data:[],msg:`2-FA Already Activated !!!`});
    
    if (req.user.twoFaUrl) 
    {
        QRCode.toDataURL(req.user.twoFaUrl, (err, imageData) =>
        {
                                                // Generate Backup Codes //
            let codesArray = [];
            if (req.user.backupCodes && req.user.backupCodes.length > 0)
                codesArray = req.user.backupCodes;
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
                User.updateOne({_id: req.user._id},{$set: {backupCodes: codesArray}}).exec();
            }
            return res.json({status: true, data: {qrData: imageData,secret: req.user.twoFaKey, backupCodes: codesArray},msg:'QR code for enabling 2 factor authentication'});
        });
    }
    else
    {
        let secret = speakeasy.generateSecret({length: 20});
        const user_secret = secret.base32;
        const otpauth_url = `${secret.otpauth_url.replace('SecretKey',req.user.email)}&issuer=${config.project_name}`;

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
        User.updateOne({_id: req.user._id},{$set: {twoFaKey: user_secret, twoFaUrl: otpauth_url, backupCodes: codesArray}}, (err, saved)=>
        {    
            if (err) return handleError(res, err);
            else if (saved.nModified)
            {
                QRCode.toDataURL(otpauth_url, (err, imageData)=>
                {
                    return res.json({status: true,data:{qrData: imageData, secret: user_secret, backupCodes: codesArray},msg:'QR code for enabling 2 factor authentication.'}); // A data URI for the QR code image
                });
            }
            else return res.json({status: false,data:[],msg:'Something went wrong. Please try again'});
        })
    }  
}
                                                    /**
                                                        * Verify 2-FA Auth using Token
                                                    **/
exports.verify2Factor = (req, res)=>
{
    if (!req.body.token_code || req.body.token_code == '')
        return res.json({status: false,data:[],msg:'Please provide code to verify'});

    User.findOne({_id:req.user._id}).lean().then((userfound)=>
    {
        if (userfound)
        {
            if (userfound.twoFaKey)
            {
                let verified = speakeasy.totp.verify({ secret: userfound.twoFaKey, encoding: 'base32', token: req.body.token_code });
                if (verified)
                {
                    loginNotification(req, userfound, res, (cbData)=>
                    {
                        User.updateOne({_id: req.user._id, twoFaEnabled: false},{$set: {twoFaEnabled: true}}).lean().exec();
                        return res.json({status: true,data:{token:cbData.token,first_login:cbData.is_first_login,referral_code:cbData.ref_code},msg:'Sucessfully Authenticated !!!'});
                    });
                }
                else return res.json({status: false,data:verified,msg:'Invalid code'});
            }
            else return res.json({status: false,data:[],msg:'Please set up two factor authentication'});
        }
        else return res.json({status: false,data:[],msg:'Something went wrong. Please try again'});
    });
}
                                                    /**
                                                        * Disable 2-FA Auth
                                                    **/
exports.disable2Factor = (req, res) =>
{
    User.updateOne({_id: req.user._id},{$set: {twoFaEnabled: false},$unset: {twoFaUrl: 1, twoFaKey: 1, backupCodes: 1}}).exec((error, status) =>
    {
        if (error) return handleError(res, err);
        else if (status.nModified)
            return res.json({status: true,data:[],msg:'Disabled 2 Factor authentication'});
        return res.json({status: false,data:[],msg:'Something went wrong. Please try again'});
    });
}
                                                    /**
                                                        * Verify Backup Code
                                                    **/
exports.verifyBackupCode = (req, res)=>
{
    if (!req.body.key)
        return res.json({status: false,data:[],msg:'Please provide one of your backup codes'});
    if (req.user.backupCodes && req.user.backupCodes.length > 0) 
    {
        let codes = req.user.backupCodes;
        const index = codes.indexOf(`${req.body.key}`);
        if (index >= 0)
        {
            codes.splice(index, 1);
            User.updateOne({_id: req.user._id}, {$set: {backupCodes: codes}}).exec();
            return res.json({status: true, data: codes, msg: 'Successfully verified'});
        }
        else return res.json({status: false, data:[], msg:'Invalid key'});
    }
    else return res.json({status: false, data:[], msg:'No backup codes found'});
}

function configureIpNotification(req, user, next)
{
    let randcode = "";
    let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < 5; i++) randcode += possible.charAt(Math.floor(Math.random() * possible.length));
    const dateNow = new Date();
    User.updateOne({_id: user._id}, {$set: {ipVerifyKey: randcode, updatedBy: user._id, updatedAt: dateNow}},(error, status)=>
    {
        if(error) next(false);
        else if(status.nModified)
        {
            let activation_link = `${config.clientdomain}/api/users/verifyIp/${randcode}`;
            const templatePath = "mail_templates/sign_up.html";
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
                subject: config.project_name + ' - IP Verification',
                html: templateContent
            }

            config.mailTransporter.sendMail(data, (error, info) =>
            {
                if (error) next(false)
                else next(true)
                console.log('Email sent:', info.envelope);
            });
        }
        else next(false)
    });
}

function loginNotification(req, userfound, res, next)
{
    const templatePath = "mail_templates/sign_in.html";
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

    const isFirstLogin = userfound.lastLogin ? false : true;
    let token = jwt.sign({_id: userfound._id }, config.secrets.session, { expiresIn: 60*60*3,algorithm: 'HS256' });
    
    logging.newlog(req,userfound._id);

    const dateNow = new Date();
    User.updateOne({_id: userfound._id},{$set:{lastLogin: dateNow, lastLoginFrom: req._remoteAddress}}).exec();
    
    next({token:token,firstLogin:isFirstLogin});
}

const validationError = (res, err)=>
{
    return res.status(422).json({status: false,data:err,msg:'Something went wrong'});
};

function handleError(res, err)
{
    return res.status(500).send({status: false,data:err,msg:'Something went wrong'});
};