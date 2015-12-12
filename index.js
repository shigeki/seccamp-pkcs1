const https = require('https');
const querystring = require('querystring');
const fs = require('fs');
const r = require('jsrsasign');
const port = 443;
const default_page = fs.readFileSync('./default_page.html');
const KEYUTIL = r.KEYUTIL;
const RSAKey = r.RSAKey;
const BigInteger = r.BigInteger;

const certdir = '/var/tmp/';
var opts = {
  cert: fs.readFileSync(certdir + 'server.cert'),
  key: fs.readFileSync(certdir + 'server.key'),
  ca: fs.readFileSync(certdir + 'server.ca')
};

function outputErrorlog(req, errormsg) {
  var remoteAddress = req.socket.remoteAddress;
  var now = (new Date()).toString();
  console.log('Error:', remoteAddress, now, errormsg);
}

function outputLog(req) {
  var remoteAddress = req.socket.remoteAddress;
  var now = (new Date()).toString();
  var method = req.method;
  var url = req.url;
  var headers = req.headers;
  var user_agent = headers['user-agent'];
  console.log('LOG:', remoteAddress, now, method, url, user_agent);
}

function derivePKCS1(modulus, public_exponent, resolved_prime) {
  var rsa = new RSAKey();
  var N = new BigInteger(modulus, 16);  // PxQ
  var E = new BigInteger(public_exponent, 10);
  var P = new BigInteger(resolved_prime, 16);
  var Q = N.divide(P);
  var P1 = P.subtract(BigInteger.ONE); // P-1
  var Q1 = Q.subtract(BigInteger.ONE); // Q-1
  var phi = P1.multiply(Q1);           // (P-1)*(Q-1)
  var D = E.modInverse(phi);           // E^-1 mod(phi)
  var DP = D.mod(P1);                  // D mod(P-1)
  var DQ = D.mod(Q1);                  // D mod(Q-1)
  var C = Q.modInverse(P);             // Q^-1 mode(P)
  rsa.setPrivateEx(N.toString(16), E.toString(16), D.toString(16),
                   P.toString(16), Q.toString(16), DP.toString(16),
                   DQ.toString(16), C.toString(16));
  var pkey = KEYUTIL.getKey(rsa);
  var pem = KEYUTIL.getPEM(pkey, "PKCS8PRV");
  return pem;
}


function writeRes(res, page) {
  res.writeHead(200,
                {'content-type': 'text/html',
                 'content-length': Buffer.byteLength(page)});
  res.end(page);
  return true;
}


function writeResError(res, error) {
  var page = '<html><head><title>Data Error</title></head>' +
      '<body>Data Error' +
      '<br><a href="/">Return</a></body></html>';
  writeRes(res, page);
  return false;
}


function ErrorCheck(req, res, modulus, public_exponent, resolved_prime) {
  var ret = true;
  var nohex_pattern = /[^0-9,a-f,A-F]/;
  var no_decimal_pattern = /[^0-9]/;
    if (nohex_pattern.test(modulus)) {
      ret = writeResError(res, 'Modulus');
      outputErrorlog(req, 'Modulus Error ');
    }

    if (no_decimal_pattern.test(public_exponent)) {
      ret = writeResError(res, 'Public Exponent ');
      outputErrorlog(req, 'Public Exponent Error ');
    }

    if (nohex_pattern.test(resolved_prime)) {
      ret = writeResError(res, 'Resolved Prime: ');
      outputErrorlog(req, 'Resolved Prime Error: ');
    }

  return ret;
}

function parsePost(req, res) {
  var buflist = [];

  req.on('data', function(d) {
    buflist.push(d);
  });

  req.on('end', function() {
    var space_cr_colon = /\s+|\r+|\n+|:+/g;
    var postData = Buffer.concat(buflist).toString();
    var obj = querystring.parse(postData);
    var modulus = obj.modulus.replace(space_cr_colon, '');
    var public_exponent = obj.public_exponent.replace(space_cr_colon, '');
    var resolved_prime = obj.resolved_prime.replace(space_cr_colon, '');

    if (!ErrorCheck(req, res, modulus, public_exponent, resolved_prime))
      return;

    try {
      var pem = derivePKCS1(modulus, public_exponent, resolved_prime);
      var page = '<html><head><title>Private Key</title>' +
          '<style>pre {font-family : Consolas,monospace;}</style></head><body><pre>' +
          pem + '</pre><br><br><a href="/">Return</a></body></html>';
      writeRes(res, page);
    } catch(e) {
      writeResErrro(res, 'RSA calculation');
    }
  });
}


function showDefaultPage(res) {
  res.writeHead(200,
                {'content-type': 'text/html',
                 'content-length': Buffer.byteLength(default_page)});
  res.end(default_page);
}


var server = https.createServer(opts, function(req, res) {
  outputLog(req);

  switch(req.method) {
    case 'POST':
    parsePost(req, res);
    break;
  default:
    showDefaultPage(res);
  }
});


server.listen(port, function() {
    console.log('Listening on ' + port);
});
