const mongoose = require('mongoose');

const bcrypt = require('bcrypt');
const saltRounds = 10;

const jwt = require('jsonwebtoken');

const userSchma = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email : {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})


userSchma.pre('save', function(next) {

    var user = this;

    // 비밀번호가 바뀔 경우에만
    if(user.isModified('password')) {

        // 비밀번호를 암호화 한다.
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if(err) return next(err)

            bcrypt.hash(user.password, salt, function(err, hash) {
                if(err) return next(err)
                user.password = hash;
                next();
            })
        })    
    } else {
        next();
    }  
})


userSchma.methods.comparePassword = function(plainPassword, cb) {
    // plainPassword 123456 암호화된 비밀번호 fasfdasd241fds
    bcrypt.compare(plainPassword, this.password, function(err, isMath) {
        if(err) return cb(err);

        cb(null, isMath);
    })
}

userSchma.methods.generateToken = function(cb) {

    var user = this;

    // jsonwebtoken을 이용해서 token을 생성하기
    var token = jwt.sign(user._id.toHexString(), 'secretToken');

    user.token = token;
    user.save(function(err, user) {
        if(err) return cb(err)

        cb(null, user)
    })
}


const User = mongoose.model('User', userSchma)

module.exports = {User}

