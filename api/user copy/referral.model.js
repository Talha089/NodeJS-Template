'use strict';

var mongoose = require('mongoose'),
    Schema = mongoose.Schema;

var ReferralSchema = new Schema(
{
  user_id:{ type: Schema.Types.ObjectId, ref: 'User' },
  
  referral_code: String,

  l1:[{type:Schema.Types.ObjectId, ref: 'User'}],
  
  l1_codes:[],

  last_updated:{ type: Date, default: Date.now() }
});

module.exports = mongoose.model('Referral', ReferralSchema);