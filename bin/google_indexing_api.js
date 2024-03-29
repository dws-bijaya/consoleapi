var request = require("request");
const fs = require('fs');
var { google } = require("googleapis");
var token_file = process.argv[2]
var urls_file = process.argv[3]
var update_mode = process.argv[4]
var key = require(token_file);



const jwtClient = new google.auth.JWT(
    key.client_email,
    null,
    key.private_key,
    ['https://www.googleapis.com/auth/indexing'],
    null
);


const batch = fs
    .readFileSync(urls_file)
    .toString()
    .split('\n');

jwtClient.authorize(function (err, tokens) {
    if (err) {
        console.log(tokens)
        console.log(err);
        return;
    }

    const items = batch.map(line => {
        return {
            'Content-Type': 'application/http',
            'Content-ID': '',
            body:
                'POST /v3/urlNotifications:publish HTTP/1.1\n' +
                'Content-Type: application/json\n\n' +
                JSON.stringify({
                    url: line,
                    type: update_mode
                })
        };
    });

    const options = {
        url: 'https://indexing.googleapis.com/batch',
        method: 'POST',
        headers: {
            'Content-Type': 'multipart/mixed'
        },
        auth: { bearer: tokens.access_token },
        multipart: items
    };
    request(options, (err, resp, body) => {
        console.log(body);
    });
});