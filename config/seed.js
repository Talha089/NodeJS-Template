					/**
					 * Populate DB with sample data on server start
					 * to disable, edit config/environment/index.js, and set `seedDB: false`
					 */

'use strict';

const User = require('../api/user/user.model');
const Countries = require('../api/countries/countries.model');
const countrySeed = require('../api/countries/countries.seed.json');

												//  Create Admin  //

User.findOne({role:'admin'}).exec((er1,adminFound)=>
{
	if (!adminFound)
	{
		let adminObj = new User(
		{
			name: 'Admin',
			uname: 'admin',
			email: 'admin@exchange.com',
			role: 'admin',
			password: 'Admin@2018',
			source: 'local',
			email_verified: true,
			is_active: true
		});
		adminObj.save((er1,saved)=>
		{
			if(saved)
				console.log('Admin Created');
		});
	}
})

											//Add countries
Countries.find({}).exec((er1,countries)=>
{
	if (countries.length == 0)
		Countries.create(countrySeed);
});
