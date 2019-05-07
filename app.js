var createError = require('http-errors');
var express = require('express');
var path = require('path');
var logger = require('morgan');
let cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const mongoose = require("mongoose");
const env = require('./config/env');
var app = express();
global.__basedir = __dirname;
app.use(logger('dev'));
app.use(express.json());
app.set("view engine", "ejs");
app.set("views", __dirname + "/views");
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


// SESSION;;

app.use(
  session({
    key: "user_sid",
    secret: "somerandonstuffs",
    resave: false,
    secure: false,
    saveUninitialized: false,
    cookie: {
      expires: 1000000000
    }
  })
);


/*
=================================================
    Initialising The Passport Middleware Required
=================================================
*/
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});
app.get('/',function(req,res){
  res.render('signup');
});
mongoose.Promise = global.Promise;
// Connect to mongoose
mongoose.set("useCreateIndex", true);
mongoose
  .connect(env.common.mongodbLink, { useNewUrlParser: true })
  .then(() => console.log("MongoDB Connected..."));
app.use('/',require('./routes/api'));

app.set("port", env.common.port);
app.listen(app.get("port"), () => {
  console.log(`Server started on port ` + app.get("port"));
});

module.exports = app;
