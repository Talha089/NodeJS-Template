'use strict';

let mongoose = require('mongoose');
let Schema = mongoose.Schema;

let PropertySchema = new Schema(
{
    title: {type: String, required: true},
    type: {type: String, required: true},
    payout: String,
    country: String,
    targetPeriod: Date,
    minInvestment: Number,
    targetRoi: Number,
    papers: Object,
    annualIncome: Number,
    location: String,
    sqtArea: String,
    price: Number,
    demand:  Number,
    currency: String,
    volume: Number,
    totalLiquidity: Number,
    document: Object,
    resources: Object,
    features: Object,
    pictures: Object,
    contract: Object,
    updatedAt:{type: Date, default: Date.now()},
    createdAt:{type: Date, default: Date.now()},
    userId:{type: Schema.Types.ObjectId, ref: 'User'},
    createdBy:{type: Schema.Types.ObjectId, ref: 'User'},
    updatedBy:{type: Schema.Types.ObjectId, ref: 'User'}
});

module.exports = mongoose.model('property', PropertySchema);
