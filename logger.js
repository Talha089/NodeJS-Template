var winston = require('winston');
var fs = require('fs');
 
var currentdate = new Date().toJSON().slice(0,10);
var tempcurrenttime = new Date().toJSON().slice(11,19);
var currenttime = tempcurrenttime.replace(/:/g, "-");
var logfilename = currentdate;

                                            //checking exception file size
fs.stat(__dirname+'/logs' + '/exceptions/exceptions_'+logfilename+'.log', (error, stat)=>
{
    if (error)
        console.log('No Exception file created for today');
    if (stat !== undefined)
    {
        if (stat.size > 10000000)
        {
        fs.rename(__dirname+'/logs' + '/exceptions/exceptions_'+logfilename+'.log', __dirname+'/logs' + '/exceptions/exceptions_'+logfilename+'_'+currenttime+'.log', (err)=>
        {
            if (err)
            console.log('error renaming exception file');
        });
        }
    }
});

var logger = winston.createLogger(
{
    transports: [
    // new (winston.transports.Console)({ json: false, timestamp: true}),
    new winston.transports.File({ filename: __dirname+'/logs' + '/debug_'+logfilename+'.log', json: false })

    /*new (winston.transports.File)({
            name: 'info-file',
            filename: __dirname+'/logs' + '/info_'+logfilename+'.log',
            level: 'info'
        }),
    new (winston.transports.File)({
        name: 'error-file',
        filename: __dirname+'/logs' + '/error_'+logfilename+'.log',
        level: 'error'
        }),
    new (winston.transports.File)({
        name: 'debug-file',
        filename: __dirname+'/logs' + '/debug_'+logfilename+'.log',
        level: 'debug'
        })*/
    ],
    exceptionHandlers: [
    //new (winston.transports.Console)({ json: false, timestamp: true }),
    new winston.transports.File({ filename: __dirname+'/logs/exceptions' + '/exceptions_'+logfilename+'.log', json: false })
    ],
    exitOnError: false
});

module.exports = logger;