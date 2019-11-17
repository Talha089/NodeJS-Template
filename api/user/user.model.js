'use strict';

let mongoose = require('mongoose');
let Schema = mongoose.Schema;
let crypto = require('crypto');

let UserSchema = new Schema(
{
  name: String,
  uname: String,
  avatar: String,
  phone: String,
  hashedPassword: String,
  tempPassword: String,
  email: { type: String, lowercase: true },
  role: { type: String, default: 'user' },
  salt: String,
  emailVerifyKey: String,
  emailVerified:{ type: Boolean, default: false },
  twoFaKey: String,
  twoFaUrl: String,
  twoFaEnabled:{ type: Boolean, default: false },
  ipVerifyKey: String,
  smsVerifyKey: String,
  smsVerifyEnabled:{ type: Boolean, default: false },
  isKycVerified:{ type: String, default:'InComplete' },
  isAccredited:{ type: Boolean, default: false },
  isActive:{ type: Boolean, default: false },
  isTermAccepted:{ type: Boolean, default: false },
  timezone:{ type: String, default: 'GMT' },
  webLoginStatus:{ type: Boolean, default: false },
  appLoginStatus:{ type: Boolean, default: false },
  lastLoginFrom:{ type: Date },
  lastLogin:{ type: Date },
  updatedAt:{ type: Date, default: Date.now() },
  createdAt:{ type: Date, default: Date.now() },
  createdBy:{ type: Schema.Types.ObjectId, ref: 'User' },
  updatedBy:{ type: Schema.Types.ObjectId, ref: 'User' }
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
                                                            **/

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
    let self = this;
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

let validatePresenceOf = function(value)
{
  return value && value.length;
};

                                                            /**
                                                             * Pre-save hook
                                                            **/
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
                                                              **/
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
  **/
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
  **/
  encryptPassword: function(password)
  {
    if (!password || !this.salt) return '';
    let salt = new Buffer(this.salt, 'base64');
    return crypto.pbkdf2Sync(password, salt, 100000, 128, 'sha512').toString('base64');
  }
};

module.exports = mongoose.model('User', UserSchema);
