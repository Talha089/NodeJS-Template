'use strict';

const mongoose = require('mongoose'), Schema = mongoose.Schema;

const LoggingSchema = new Schema(
{
  userId:{ type: Schema.Types.ObjectId, ref: 'User' },
  ipAddress: String,
  userAgent: String,
  accessTime:{ type: Date, default: new Date() },
  accessToken: String,
  requestUrl: String,
  requestData: String,
  track:{ type: Boolean, default: false }
});

module.exports = mongoose.model('Logging', LoggingSchema);