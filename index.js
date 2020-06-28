const express = require('express')
const app = express()
const port = 5000

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser')

const config = require('./config/key');

const {User} = require("./models/User");

// application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended: true}));

// application/json
app.use(bodyParser.json());

const mongoose = require('mongoose')

mongoose.connect(config.mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useCreateIndex: true,
        useFindAndModify: false
    })
    .then(() => console.log('MongoDB Connected...'))
    .catch(err => console.log(err))

app.get('/', (req, res) => res.send('Hello World~안녕하쇼22232'))

// register router
app.post('/register', (req, res) => {

    // 회원 가입 때 필요한 정보들 DB에 넣기

    const user = new User(req.body)

    user.save((err, userInfo) => {
        if (err) 
            return res.json({success: false, err})
        return res
            .status(200)
            .json({success: true})
    })

})

app.post('/login', (req, res) => {

    // 요청된 이메일을 DB에서 찾는다.
    User.findOne({ email: req.body.email }, (err, user) => {
        if (!user) {
            return res.json({
                loginSuccess: false, message: "제공된 이메일에 해당하는 유저가 없습니다."
            })
        }

        // 이메일을 DB에 존재한다면 비밀번호를 확인한다.
        user.comparePassword(req.body.password, (err, isMatch) => {
            if (!isMatch) 
                return res.json( { loginSuccess: false, message: "비밀번호가 틀렸습니다."})
        
            // 비밀번호까지 같다면 토큰을 생성하기.
            user.generateToken((err, user) => {
                if(err) return res.status(400).send(err);

                // 토큰을 저장한다.
                res.cookie("x_auth", user.token )
                .status(200)
                .json({ loginSuccess: true, userId: user._id })

            })
        })

    })

})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))