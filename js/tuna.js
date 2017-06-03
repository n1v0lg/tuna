(function (isNode) {
    'use strict';

    var TunaService = function (Promise, wss, jsbn, paillier) {
        var utils = {};

        // TODO: if this runs in node we don't need jsbn as rng
        utils.rnd = function (bits, upper) {
            var r, rng = new jsbn.SecureRandom();
            do {
              r = new jsbn.BigInteger(bits, rng);
              // make sure r <= upper
            } while (r.compareTo(upper) > 0);
            return r;
        };

        utils.secretShare = function (val, pk) {
            /* 
             * s1 is random value between 0 and n - 1
             * s2 is val - s1 mod n
             * val = s1 + s2 % n 
             */
            var nm1 = pk.n.subtract(jsbn.BigInteger.ONE),
                s1 = this.rnd(pk.keySize, nm1),
                s2 = (val.subtract(s1)).mod(pk.n);
            return [s1, s2];
        };

        utils.defer = function () {
            var resolve, reject;
            var promise = new Promise(function () {
                resolve = arguments[0];
                reject = arguments[1];
            });
            return {
                resolve: resolve,
                reject: reject,
                promise: promise
            };
        };

        var rt = {};

        rt.defs = {};
        rt.orphans = [];
        rt.pc = 0;
        rt.socket = null;
        rt.pk = null;
        rt.p = null;

        rt.createSecret = function (val) {
            var valBi = new jsbn.BigInteger(val.toString());
            var shares = utils.secretShare(valBi, this.pk);
            var client = shares[0],
                server = shares[1];
            var secret = {
                client: Promise.resolve({
                    val: this.pk.encrypt(client),
                    pc: this.pc++
                }),
                server: {
                    val: server, 
                    pc: this.pc++
                }
            };
            return secret;
        };

        rt.prodClient = function (a1, b1) {
            // Move inside callback?
            var pc = this.pc++,
                a1b1 = utils.defer();
            this.defs[pc] = a1b1;
            var that = this;

            var clientSharesIn = Promise.join(a1, b1, pc,
                function (a1, b1, pc) {
                    var toSend = {
                        type: 'shares', 
                        body: {
                            a1: a1.val.toString(), 
                            b1: b1.val.toString(), 
                            pc: pc
                        }
                    };
                    that.socket.send(JSON.stringify(toSend));
                    return {
                        a1: a1, 
                        b1: b1
                    };
                });

            return Promise.join(clientSharesIn, a1b1.promise,
                function (clientSharesIn, a1b1) {
                    return {
                        a1: clientSharesIn.a1,
                        b1: clientSharesIn.b1,
                        a1b1: a1b1
                    };
                });      
        };

        /* 
         * compute product of secret a and secret b 
         * result will be another secret
         */
        rt.prod = function (aSec, bSec) {
            var clientShares = this.prodClient(aSec.client, bSec.client),
                that = this,
                pk = this.pk,
                nm1 = pk.n.subtract(jsbn.BigInteger.ONE),
                r = utils.rnd(pk.keySize, nm1);

            // the new client share of the product: (a1b1 + a1b2 + b1a2 + r)_pk
            var clientShareRes = clientShares.then( 
                function (clientShares) {
                    var a1 = clientShares.a1.val,
                        b1 = clientShares.b1.val,
                        a2 = aSec.server.val,
                        b2 = bSec.server.val;
                    var a1b2 = pk.mult(a1, b2),
                        b1a2 = pk.mult(b1, a2),
                        a1b1 = clientShares.a1b1.val;
                    return {
                        val: pk.addPlain(pk.add(pk.add(a1b1, a1b2), b1a2), r),
                        pc: a1b1.pc
                    };
                }
            );
            // the new server share of the product: a2b2 - r
            var serverShareRes = {
                val: aSec.server.val.multiply(bSec.server.val).mod(this.p).subtract(r).mod(this.p), 
                pc: that.pc++
            };
            var secRes = {
                client: clientShareRes,
                server: serverShareRes
            };
            return secRes;
        };

        rt.sum = function (aSec, bSec) {
            var that = this,
                pk = this.pk,
                a1 = aSec.client,
                a2 = aSec.server,
                b1 = bSec.client,
                b2 = bSec.server;

            // the new client share (a1 + b1)_pk
            var clientShareRes = Promise.join(a1, b1, function (a1, b1) {
                return {
                    val: pk.add(a1.val, b1.val),
                    pc: that.pc++
                };
            });
            // the new server share a2 + b2
            var serverShareRes = {
                val: a2.val.add(b2.val).mod(pk.n),
                pc: that.pc++
            };

            return {
                client: clientShareRes,
                server: serverShareRes
            };
        };

        rt.reveal = function (sec) {
            var that = this;
            sec.client.then(function (clientShare) {
                var toSend = {
                    type: 'result',
                    body: {
                        client: clientShare.val.toString(), 
                        server: sec.server.val.toString()
                    }
                };
                that.socket.send(JSON.stringify(toSend));
            });
        };

        // TODO: refactor into separate methods: init and runProtocol
        rt.run = function (protocol) {
            console.log('Started protocol... Waiting on client.');
            wss.on('connection', function connection (socket) {
                console.log('Client connected.');
                rt.socket = socket;
                rt.socket.send(JSON.stringify({type: 'pk', body: {}}));
                rt.socket.onmessage = function (msg) {
                    var msg = JSON.parse(msg.data),
                        type = msg.type,
                        body = msg.body;

                    if (type === 'pk') {
                        var pk = body;
                        var n = new jsbn.BigInteger(pk.n),
                            keySize = pk.keySize;
                        rt.pk = new paillier.PublicKey(keySize, n);
                        rt.p = n;
                        protocol(rt);
                    }
                    else if (type === 'share') {
                        var share = body;
                        console.log(share);
                        var pc = share.pc;
                        share.val = new jsbn.BigInteger(share.val);
                        // check if deferred w/ pc exists
                        var d = rt.defs[pc];
                        if (d) {
                            d.resolve(share);
                        }
                        else {
                            // something went wrong, server is not waiting
                            // on share with this pc
                            console.error('Orphaned share:', share);
                            rt.orphans.push(share);
                        }
                    }  
                };
            });
        };

        return rt;
    };

    if (isNode) {
        // NodeJS module definition
        module.exports = TunaService;
    }
})(typeof module !== 'undefined' && module.exports);
