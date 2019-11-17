'use strict';

var mongoose = require('mongoose'),
    Schema = mongoose.Schema;

var CountriesSchema = new Schema(
{
  altSpellings:[],
  area:Number,
  borders:[],
  callingCode:[],
  capital:String,
  cca2:String,
  cca3:String,
  ccn3:String,
  cioc:String,
  currency:[],
  demonym:String,
  landlocked:String,
  languages:{},
  latlng:[],
  name:{},
  region:String,
  subregion:String,
  tld:[],
  translations:{}
});

module.exports = mongoose.model('Countries', CountriesSchema);