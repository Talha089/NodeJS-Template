'use strict';

const fs = require('fs');
const Property = require('./property.model');
const config = require('../../config/environment');

                                                    /**
                                                        * Create new property
                                                    **/
exports.create = (req, res) =>
{
    let data = req.body;
    data['userId'] = req.user._id;
    if (!data['userId'] || data['userId'] == '' || data['userId'] == undefined || data['userId'] == null)
        return res.json({status: false,data: [], msg: 'Please Login to perform this action'});
    if (!data['title'] || data['title'] == '' || data['title'] == undefined || data['title'] == null)
        return res.json({status: false,data: [], msg: 'Please provide title'});
    if (!data['type'] || data['type'] == '' || data['type'] == undefined || data['type'] == null)
        return res.json({status: false,data: [], msg: 'Please provide type'});
    if (!data['country'] || data['country'] == '' || data['country'] == undefined || data['country'] == null)
        return res.json({status: false,data: [], msg: 'Please provide country'});
    if (!data['demand'] || data['demand'] == '' || data['demand'] == undefined || data['demand'] == null)
        return res.json({status: false,data: [], msg: 'Please provide demand'});
    if (!data['currency'] || data['currency'] == '' || data['currency'] == undefined || data['currency'] == null)
        return res.json({status: false,data: [], msg: 'Please provide currency'});
    if (!data['location'] || data['location'] == '' || data['location'] == undefined || data['location'] == null)
        return res.json({status: false,data: [], msg: 'Please provide location'});
    
    let newProperty = 
    {
        type: data['type'],
        title: data['title'],
        demand: data['demand'],
        userId: data['userId'],
        country: data['country'],
        currency: data['currency'],
        location: data['location'],
    }
    newProperty = new Property(newProperty);
    newProperty.save((error, saved)=>
    {
        if (error) return handleError(res, error);
        const templatePath = "mail_templates/sign_up.html";
        let templateContent = fs.readFileSync(templatePath, "utf8");
        templateContent = templateContent.replace("##EMAIL_LOGO##", config.mail_logo);
        templateContent = templateContent.replace(new RegExp("##PROJECT_NAME##",'gi'), config.project_name);
        templateContent = templateContent.replace("##USERNAME##", saved.title);
        templateContent = templateContent.replace("##MAIL_FOOTER##", config.mail_footer);

        const data = 
        {
            from: config.mail_from_email,
            to: req.user.email,
            subject: config.project_name + ' - Property Registered',
            html: templateContent
        }
        config.mailTransporter.sendMail(data, (error, info) =>
        {
            if (error) console.log(error);
            else console.log('Email sent:', info.envelope);
        });
        return res.json({status: true, data: saved, msg: 'Property registered successfully.'});
    });
};
                                                    /**
                                                        * Get Property Details
                                                    **/
exports.getProperty = (req, res)=>
{
    const _id = req.params.id;
    if(!_id || _id === undefined || _id === null || _id === '')
        return res.status(401).json({status: false, data: [], msg: 'Please Select Property'});
    Property.findOne({ _id }).lean().exec((error, property)=>
    {
        if (error) return handleError(res, error);
        else if (!property) return res.status(401).json({status: false, data: [], msg: 'No property found'});
        return res.json({status: true, data: property, msg: 'Property details found'});
    });
};
                                                    /**
                                                        * My Properties
                                                    **/
exports.myProperties = (req, res)=>
{
    const userId = req.user._id;
    if(!userId || userId === undefined || userId === null || userId === '')
        return res.status(401).json({status: false, data: [], msg: 'Please Select Property'});
    Property.find({ userId }).lean().exec((error, properties)=>
    {
        if (error) return handleError(res, error);
        else if (properties.length === 0) return res.status(401).json({status: false, data: [], msg: 'No user property found'});
        return res.json({status: true, data: properties, msg: 'User Properties found'});
    });
};
                                                    /**
                                                        * Update Property
                                                    **/
exports.updateProperty = (req, res)=>
{
    let updateObj = {};
    let isUpdate = false;
    let _id = req.body.id;
    if(!_id || _id === undefined || _id === null || _id === '')
        return res.json({status: false, data: [], msg: 'Please Select Property'});
    let allowedKeys = ['type', 'title', 'demand', 'country', 'currency', 'location'];
    allowedKeys.forEach(key =>
    {
        if (req.body[key])
        {
            isUpdate = true;
            updateObj[key] = req.body[key];
        }
    });
    if (isUpdate)
    {
        Property.updateOne({_id}, {$set: updateObj}, (error, status)=>
        {
            if (error) return handleError(res, error);
            if (!status.nModified)
                return res.json({status: false, data: [], msg: 'No records updated'});
            return res.json({status: true, data: [], msg: 'Property Updated Successfully'});
        });
    }
    else return res.json({status: false,data: [], msg: 'Please Provide Valid Keys'});
}


function handleError(res, err)
{
    return res.status(500).send({status: false,data:err,msg:'Something went wrong'});
};