'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var crypto = require('crypto');
var sha256 = require('sha256');

var UserSchema = new Schema(
{
  name: String,
  uname: String,
  email: { type: String, lowercase: true },
  role: { type: String, default: 'user' },
  can_track :{ type: Boolean, default: false },
  hashedPassword: String,
  provider: String,
  salt: String,
  source: String,
  contact_no: String,
  referral_code: String,
  referred_by: String,
  referral_count:{ type: Number, default: 0},
  auth_pin: String,
  avatar: { type: Number, default: 0 },
  is_affiliate:{ type: Boolean, default: true },
  is_airdrop:{ type: Boolean, default: false },
  kyc:{ type: Schema.Types.Mixed },
  is_kyc_verified:{ type: String, default:'InComplete' },
  kyc_created_at:{ type: Date },
  kyc_updated_at:{ type: Date },
  kyc_comment:{ type: String },
  web_login_status:{ type: Boolean, default: false },
  app_login_status:{ type: Boolean, default: false },
  email_verified:{ type: Boolean, default: false },
  email_verify_key: String,
  ip_verify_key: String,
  contact_verify_key: String,
  two_fa_enable:{ type: Boolean, default: false },
  contact_verify_enable:{ type: Boolean, default: false },
  two_fa_secret_key: String,
  two_fa_authurl: String,
  backup_codes:[],
  is_active:{ type: Boolean, default: false },
  is_terms_accepted:{ type: Boolean, default: false },
  temp_password: String,
  telegram_username: String,
  twitter_username: String,
  language:{ type: String, default: 'english'},
  theme:{ type: String, default: 'default' },
  timezone:{ type: String, default: 'GMT' },
  last_login: { type: Date },
  last_login_from: String,
  active_ip: String,
  active_token: String,
  created_at:{ type: Date, default: Date.now() },
  created_by:{ type: Schema.Types.ObjectId, ref: 'User' },
  updated_at:{ type: Date },
  updated_by:{ type: Schema.Types.ObjectId, ref: 'User' }
});

                                                          /**
                                                           * Virtuals
                                                          */
UserSchema
  .virtual('password')
  .set(function(password)
  {
    this._password = password;
    this.salt = this.makeSalt();
    this.hashedPassword = this.encryptPassword(password);
  })
  .get(function()
  {
    return this._password;
  });

// Public profile information
UserSchema
  .virtual('profile')
  .get(function()
  {
    return {
      'name': this.name,
      'role': this.role
    };
  });

// Non-sensitive info we'll be putting in the token
UserSchema
  .virtual('token')
  .get(function()
  {
    return {
      '_id': this._id,
      'role': this.role
    };
  });

/**
 * Validations
 */

// Validate empty email
UserSchema
  .path('email')
  .validate(function(email)
  {
    return email.length;
  }, 'Email cannot be blank');

// Validate empty password
UserSchema
  .path('hashedPassword')
  .validate(function(hashedPassword)
  {
    return hashedPassword.length;
  }, 'Password cannot be blank');

// Validate email is not taken
UserSchema
  .path('email')
  .validate(function(value)
  {
    var self = this;
    this.constructor.findOne({email: value}, function(err, user)
    {
      if(err) throw err;
      if(user) 
      {
        if(self.id === user.id)
          return true;
        return false;
      }
      return true;
    });
}, 'The specified email address is already in use.');

var validatePresenceOf = function(value)
{
  return value && value.length;
};

/**
 * Pre-save hook
 */
UserSchema
  .pre('save', function(next) 
  {
    if (!this.isNew) return next();

    if (!validatePresenceOf(this.hashedPassword))
      next(new Error('Invalid password'));
    else
      next();
  });

/**
 * Methods
 */
UserSchema.methods = {
  /**
   * Authenticate - check if the passwords are the same
   *
   * @param {String} plainText
   * @return {Boolean}
   * @api public
   */
  authenticate: function(plainText)
  {
    return this.encryptPassword(plainText) === this.hashedPassword;
  },

  /**
   * Make salt
   *
   * @return {String}
   * @api public
   */
  makeSalt: function()
  {
    return crypto.randomBytes(16).toString('base64');
  },

  /**
   * Encrypt password
   *
   * @param {String} password
   * @return {String}
   * @api public
   */
  encryptPassword: function(password)
  {
    if (!password || !this.salt) return '';
    var salt = new Buffer(this.salt, 'base64');
    return crypto.pbkdf2Sync(password, salt, 100000, 128, 'sha512').toString('base64');
  }
};

module.exports = mongoose.model('User', UserSchema);
