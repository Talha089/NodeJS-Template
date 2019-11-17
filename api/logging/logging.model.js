'use strict';

const mongoose = require('mongoose'), Schema = mongoose.Schema;

const LoggingSchema = new Schema(
{
  userId:{ type: Schema.Types.ObjectId, ref: 'User' },
  ipAddress: String,
  user_agent: String,
  access_time:{ type: Date, default: new Date() },
  access_token: String,
  request_url: String,
  request_data: String,
  track:{ type: Boolean, default: false }
});

module.exports = mongoose.model('Logging', LoggingSchema);