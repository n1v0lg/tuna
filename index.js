var express = require('express');
var app = express();
var server = require('http').createServer(app);  
var WebSocketServer = require('ws').Server;
var Promise = require('bluebird');
var jsbn = require('jsbn');
var BigInteger = jsbn.BigInteger;
var paillier = require('./js/paillier.js')(jsbn);

wss = new WebSocketServer({
    server: server
});

var tuna = require('./js/tuna.js')(Promise, wss, jsbn, paillier);

app.use(express.static(__dirname));

function vectorProd (rt) {
    var secretsA = [],
        secretsB = [],
        secretsC = [],
        numIts = 10;

    for (var i = 0; i < numIts; i++) {
        secretsA.push(rt.createSecret(i));
        secretsB.push(rt.createSecret(i));
    };

    for (var i = 0; i < numIts; i++) {
        secretsC.push(rt.prod(secretsA[i], secretsB[i]));
    };        
    
    for (var i = 0; i < numIts; i++) {
        rt.reveal(secretsC[i]);
    };
};

function vectorSum (rt) {
    var secretsA = [],
        numIts = 10;

    for (var i = 0; i < numIts; i++) {
        secretsA.push(rt.createSecret(i));
    };

    var res = secretsA[0];
    for (var i = 1; i < numIts; i++) {
        res = rt.sum(res, secretsA[i]);
    };        
    
    rt.reveal(res);
};

function sumOfSquares (rt) {
    var secretsA = [],
        numIts = 10;

    for (var i = 0; i < numIts; i++) {
        secretsA.push(rt.createSecret(i));
    };

    for (var i = 0; i < numIts; i++) {
        secretsA[i] = rt.prod(secretsA[i], secretsA[i]);
        rt.reveal(secretsA[i]);
    };

    var res = secretsA[0];
    for (var i = 1; i < numIts; i++) {
        res = rt.sum(res, secretsA[i]);
    };
    
    rt.reveal(res);
};

function singleSum (rt) {
    var a = rt.createSecret(100),
        b = rt.createSecret(50),
        c = rt.sum(a, b);
    rt.reveal(c);
};

function singleProd (rt) {
    var a = rt.createSecret(100),
        b = rt.createSecret(50),
        c = rt.prod(a, b);
    rt.reveal(c);
};

function dummyProtocol (rt) {
    rt.reveal(rt.createSecret(100));
};

tuna.run(sumOfSquares);

server.listen(8080);

