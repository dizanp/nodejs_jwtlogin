//==============Set Up
var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var jwt = require('jsonwebtoken');
var app = express();
var router = express.Router();
var cors = require('cors');


//======Set Up Local
var config = require('./app/config');
var User = require('./app/models/user');
var port = 3000;

app.use(bodyParser.urlencoded({extended:false}));
mongoose.connect(config.database, { useNewUrlParser: true });
app.set('secretKey', config.secret);
app.use(cors());

//==============Router API
router.post('/login', function(req,res){
    
    User.findOne({
        email : req.body.email
    }, function(err, user){
        if(err) throw err;

        if(!user){
            res.json({ succes: false, message: 'User tidak ada di database' });
        }else{
            if (user.password != req.body.password){
                //harusnya password di hash
                res.json({ succes: false, message: 'Password salah' });
            }else{
                //membuat token
                var token = jwt.sign(user.toJSON(), app.set('secretKey'), {
                    expiresIn: "24h"
                });

                //mengirim balik token
                res.json({
                    succes  : true, 
                    message : 'token berhasil di dapatkan',
                    token   : token
                });
            }
        }
    });

});

router.get('/', function(req,res){
    res.send('ini di route home');
});

//proteksi route dengan token
router.use(function(req, res, next){
    //mengambil token: req.body.token || req.query.token ||
    var token = req.headers['authorization'];

    //decode token
    if(token){
        jwt.verify(token, app.get('secretKey'), function(err, decoded){
            if(err){
                return res.json({succes: false, message:'problem dengan token'});
            }else{
                req.decoded = decoded;

                //cek apakah token sudah expired
                if(decoded.exp <= Date.now()/1000){
                    return res.status(400).send({
                        succes  : false, 
                        message : 'token sudah expired',
                        date    : Date.now()/1000,
                        exp     : decoded.exp
                    });
                }

                next();
            }
        });
    }else{
        return res.status(403).send({
            succes: false,
            message: 'token tidak tersedia'
        });
    }
});

router.get('/users', function(req, res){
    User.find({}, function(err, users){
        res.json(users);
    });
});

router.get('/profile', function(req, res){
    res.json(req.decoded);
    console.log(req.decoded);
});

//prefix api
app.use('/api', router);

app.listen(3000);