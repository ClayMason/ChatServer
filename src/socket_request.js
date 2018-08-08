var req = require('request')

const options = {
  url: 'localhost:80',
  method: 'GET',
  headers: {
    // TODO
    'Upgrade': 'websocket',
    'Connection': 'Upgrade',
  }
};

request(options, function(err, res, body){
  if ( err ) console.log("Error in request");
  else console.log(JSON.parse(body));
});
