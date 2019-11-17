'use strict';

const ip = require('ip');
const _ = require('lodash');
const path = require('path');
const express = require('express');
const nodemailer = require('nodemailer');

const isProduction = false;
const port_no = process.env.PORT || 3000;

process.env.IP = ip.address();
process.env.NODE_ENV = process.env.NODE_ENV || 'development';
process.env.jwtSecret = '$2a$06$GXmQiERBvYRGD91bIJLWRO2m4WGUpj7IRuSuve3pZ3B5rRtLIzm2G';

const all = {
    project_name: 'Tokenism',
    env: process.env.NODE_ENV,
    isProduction : isProduction,
                                        // Frontend path to server
    
    assets: express.static(__dirname + '/../../../view'),
    view: path.normalize(__dirname + '/../../../view/index.html'),

                                            // Server port
    port: process.env.PORT || 3000,

                                            // Server IP
    ip: process.env.IP || '0.0.0.0',

                                // Should we populate the DB with sample data ?
    seedDB: true,

    secrets: { session: 'Tokenism_s3cr3t_2018' },
                                        // List of user roles
    userRoles: ['guest', 'user', 'affiliateAdmin', 'kycAdmin', 'admin'],

    mailTransporter:nodemailer.createTransport(
    {
        host:'smtp.mailgun.org',
        port: 587,
        secure: false,
        auth:{
            user: 'postmaster@maishince.com',
            pass: '0504c8cc3d2bd071c7fc598e7903d4db-e51d0a44-9916ec92'
        }
    }),
    mail_from_email: 'Tokenism info@tokenism.com',
    mail_from_name: 'Tokenism',
    mail_footer: 'The Tokenism Team',
    mail_logo: 'https://tokenism.com/assets/pic/logo.png',
    support_title: 'Tokenism Support',
    support_email: 'info@tokenism.com',

                                            // Twillio Configurations
    twillio:{
        from:'+14044619210',
        accountSid: 'ACa756cefa2d0a7b2b76a642d76763355f',
        authToken: '5e835c8f679f92fc11b482aa9086b216',
    },

    thisdomain: 'http://'+ip.address()+':'+port_no,
    clientdomain: isProduction ? 'https://tokenism.com' : 'http://localhost:3000',
    exchange_server: isProduction ? 'http://139.59.19.210:3000' : 'http://192.168.0.128:3102',

    pepper: '78uA_PPqX&@$',
    encPass : 's1XrWeMEc2aJn1tu5HMp',
    rpc_secret:"4b8cf527e04e4a8abe40d9b2030129fckf546pwsdafe",
};

                                /* Export the config object based on the NODE_ENV*/
                                /*===============================================*/

module.exports = _.merge( all, require('./' + process.env.NODE_ENV + '.js') || {});
