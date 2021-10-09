const express = require('express');
const cors = require('cors');
const passport = require('passport');

//-------------- GENERAL SETUP ----------------
require('dotenv').config();

var app = express();
require('./auth/passport')(passport);

app.use(passport.initialize());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cors());

// -------------- Routes ----------------
app.use(require('./auth/routes'));

// -------------- SERVER ----------------
app.listen(5000);
console.log("Listening on port 5000");