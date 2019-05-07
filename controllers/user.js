var passport = require("passport"),
  LocalStrategy = require("passport-local").Strategy;
var User = require("../models/user");
const express = require("express");
const router = express.Router();
const env = require("../config/env");
const fs = require("fs");
const bcrypt = require("bcrypt-nodejs");
const handlebars = require("handlebars");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const validator = require("email-validator");
const passwordvalidate = require("password-validator");
let jwt = require("jsonwebtoken");
let config = require("../config/jwtokenconfig");
const url = require("url");
var schema = new passwordvalidate();
schema
  .is()
  .min(8) // Minimum length 8
  .is()
  .max(100) // Maximum length 100
  .has()
  .uppercase() // Must have uppercase letters
  .has()
  .lowercase() // Must have lowercase letters
  .has()
  .digits() // Must have digits
  .has()
  .not()
  .spaces();

// =========================================================================
// LOCAL LOGIN =============================================================
// =========================================================================
class UserController{
async signin(req, res, next) {
  console.log(req.body);
  passport.authenticate("local", function(err, data, message) {
    if (err) {
      return next(err);
    }
    if (!data) {
      return res.send({
        status: false,
        message: message
      });
    }
    
    User.findOne({ _id: data._id }, async (err, user) => {
        
        req.logIn(data, function(err) {
          if (err) {
            return next(err);
          }
          
          let token = jwt.sign({ username: user.username }, config.secret, {
            expiresIn: "24h" // expires in 24 hours
          });
          // return the JWT token for the future API calls
          req.session.token = token;
          res.json({
            status: true,
            message: "Authentication successful!",
            user: data,
            token: token
          });
        });
      
    });
    
  })(req, res, next);
}

async signup(req, res) {
  passport.authenticate("local-signup", function(err, data, message) {
    if (err) {
      return next(err);
    }
    if (!data) {
      return res.json({
        status: false,
        message: message
      });
    }
    return res.json({
      status: true,
      message: "Signup successfull. Please verify your email."
    });
  })(req, res);
}

async verify(req, res) {
  let urlparse = url.parse(req.url, true);
  let id = urlparse.query.id;
  if (
    req.protocol + "://" + req.get("host") ==
    "http://" + env.dev.app_callback
  ) {
    console.log("Checking if req is from known source");

    User.findOne({ token: id }, function(err, user) {
      console.log("finding for user with same token");

      if (user) {
        console.log("Is User");
        user.isVerified = true;
        user.save();
        res.json({
          status: true,
          message: "Email Verification completed..."
        });
      }
    });
  } else {
    res.json({
      status:false,
      message: "Request is from unknown source"
    });
  }
}

}

passport.use(
  "local",
  new LocalStrategy(
    {
      // by default, local strategy uses username and password, we will override with email
      usernameField: "username",
      passwordField: "password",
      passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, username, password, done) {
      process.nextTick(function() {
        User.findOne({ username: username }, function(err, user) {
          // if there are any errors, return the error
          if (err) return done(err);
          // if no user is found, return the message
          if (!user) {
            return done(
              null,
              false,
              "No user Found..Please check the credentials"
            );
          }

          if (!user.validPassword(password)) {
            return done(null,false,"Incorrect Password");
          }
          // all is well, return user
          else {
            if (user.isVerified) {
              return done(null, user);
            } else {
              return done(null,false,"Please verify your email");
            }
          }
        });
      });
    }
  )
);

// =========================================================================
// LOCAL SIGNUP ============================================================
// =========================================================================
// Routes to local signup and login;

passport.use(
  "local-signup",
  new LocalStrategy(
    {
      // by default, local strategy uses username and password, we will override with email
      usernameField: "username",
      passwordField: "password",
      passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, username, password, done) {
      let { email, cpassword } = req.body;
      email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching
      let validate = validator.validate(email);
      var pass_validate = schema.validate(password, { list: true });
      if (validate === true && password === cpassword) {
        if (
          pass_validate.indexOf("min") == -1 &&
          pass_validate.indexOf("max") == -1 &&
          pass_validate.indexOf("uppercase") == -1 &&
          pass_validate.indexOf("digits") == -1 &&
          pass_validate.indexOf("spaces") == -1
        ) {
          // asynchronous
          process.nextTick(function() {
            // Email and password validation

            //validation => END
            // To Avoid Signup using existing email
            User.findOne({ username: username }, function(err, user) {
              // if there are any errors, return the error
              if (err) {
                return done(err);
              }

              // check to see if theres already a user with that email
              if (user) {
                return done(null,false,"Username taken");
              } else {
                token = crypto.randomBytes(16).toString("hex");
                // create the user
                const newUser = new User({
                  email: email,
                  username: username,
                  password: generateHash(password),
                  isVerified: false,
                  token:token
                });

                newUser.save(function(err, user) {
                  if (err) {
                    if (err.name === "MongoError" && err.code === 11000) {
                      console.log("There was a duplicate key error" + err);
                      User.findOne({email:newUser.email},function(err,user){
                        if(err) return done(err);
                        return done(null,false,"Email already exists");
                      })
                    } else {
                      return done(err);
                    }
                  } else {
                    //Mail for verification ->Start
                    let transporter = nodemailer.createTransport({
                      service: "Gmail",
                      auth: {
                        user: "decoymail95@gmail.com",
                        pass: "decoy95mail"
                      }
                    });
                    fs.readFile(
                      __basedir +
                        "/files/emailTemplates/emailVerifyTemplate.html",
                      { encoding: "utf-8" },
                      function(err, html) {
                        link =
                          "http://" +
                          env.dev.app_callback +
                          "/verify?id=" +
                          token;

                        var template = handlebars.compile(html);
                        var replacements = {
                          link: link
                        };
                        var emailtemplate = template(replacements);

                        // var rand,mailOptions,host,link;
                        let mailOptions = {
                          from: '"Appname " <noreply@gmail.com>', // sender address
                          to: email, // list of receivers
                          subject: "Mail Verification", // Subject line
                          html: emailtemplate
                        };
                        // send mail with defined transport object
                        transporter.sendMail(mailOptions, (error, info) => {
                          if (error) {
                            return done(error);
                          }
                          console.log("Message sent: %s", info.messageId);
                          // Preview only available when sending through an Ethereal account
                          console.log(
                            "Preview URL: %s",
                            nodemailer.getTestMessageUrl(info)
                          );
                        });
                      }
                    ); // read File for template
                    //End

                    return done(
                      null,
                      user
                    );
                  }
                });
              }
            }); // User.find ends

            // else ends
            // if ends
          });
        } else {
          return done(
            null,
            false,
            "Password must be 8-100 characters long, must have an uppercase, a digit & no spaces"
          );
        }
      } else {
        return done(
          null,
          false,
          "Invalid Email format or Non-matching password"
        );
      }
    }
  )
);

function generateHash(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
}

module.exports = new UserController();
