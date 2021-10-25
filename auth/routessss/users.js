const router = require('express').Router();
const passport = require('passport');
const connection = require('../../db/database');
const User = connection.models.User;
const utils = require('../utils');

router.get('/protected', passport.authenticate('jwt',{session:false}) ,(req, res, next) => {
    res.json({ success: true, msg:"authorized" });
});

router.post('/login', function (req, res, next) {
    User.findOne({ username: req.body.username })
        .then((user) => {
            if (!user) {
                res.json({ success: false, msg:"User not created" });
            }
            const isValid = utils.validPassword(req.body.password, user.hash, user.salt);
            if (isValid) {
                const jwt = utils.issueJWT(user);

                res.json({
                    success: true,
                    user: user,
                    token: jwt.token,
                    expiresIn: jwt.expires
                });

            } else {
                res.json({ success: false, msg:"Password not valid" });
            }
        })
        .catch((err) => {
            next(err);
        });
});

router.post('/register', function (req, res, next) {
    const passwordObj = utils.genPassword(req.body.password);
    const newUser = new User({
        username: req.body.username,
        hash: passwordObj.hash,
        salt: passwordObj.salt
    });
    console.log(newUser);

    newUser.save()
        .then((user) => {
            console.log(`user created ${user}`);

            const jwt = utils.issueJWT(user);

            res.json({
                success: true,
                user: user,
                token: jwt.token,
                expiresIn: jwt.expires
            });
        })
        .catch(err => next(err));
});

module.exports = router;