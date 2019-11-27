/**
 * Using Rails-like standard naming convention for endpoints.
 * GET     /things              ->  index
 * POST    /things              ->  create
 * GET     /things/:id          ->  show
 * PUT     /things/:id          ->  update
 * DELETE  /things/:id          ->  destroy
 */

'use strict';

var _ = require('lodash');
var Countries = require('./countries.model');
var async = require('async');

                                            // Get list of countries
exports.index = function(req, res)
{
  Countries.find({},{demonym:1,"name.common":1}).exec((err, countriesList)=>
  {
    if(err) 
        return handleError(res, err);
    return res.status(200).json({status: true,data:countriesList,msg:'List of countries'});
  });
};

// exports.dumpCountries = function(req, res){
//   async.forEachOf(req.body.nationalities,function(val,ke,cb){
//       let countryObj = {};
//       countryObj['nationality'] = val['nationality_name'];
//       const finalCountryObj = new Countries(countryObj);
//       finalCountryObj.save(function(err, savedCountry){})
//       setTimeout(cb, 100);
//   },function(err){
//       return res.json("done");
//   })
// }

// exports.dumpCountriesList = function(req, res){
//   async.forEachOf(req.body.countries,function(val,ke,cb){
//       let countryObj = {};
//       countryObj['name'] = val['name'];
//       countryObj['code'] = val['code'];
//       const finalCountryObj = new CountriesList(countryObj);
//       finalCountryObj.save(function(err, savedCountry){})
//       setTimeout(cb, 100);
//   },function(err){
//       return res.json("done");
//   })
// }

function handleError(res, err)
{
  return res.status(500).send(err);
}