const fs = require('fs');
const path = require('path');
const User = require('../db/database').models.User;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const pathToKey = path.join(__dirname, '../keys/id_rsa_pub.pem');
const PUB_KEY = fs.readFileSync(pathToKey, 'utf8');

const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: PUB_KEY,
    algorithm: ['RS256']
};

function verifyCallack(payload, done) {
    User.findOne({ _id: payload.sub })
        .then((user) => {
            if (user) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        })
        .catch(err => {
            done(err, null)
        });
}

const strategy = new JwtStrategy(options, verifyCallack);

module.exports = (passport) => {
    passport.use(strategy);
}