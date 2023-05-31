require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const ejs = require("ejs");
const connection = require("../utils/db");
const session = require("express-session");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const async = require("async");
const fileUpload = require("express-fileupload");
const passport = require("passport");
const cookieParser = require("cookie-parser");
const passportLocalMongoose = require("passport-local-mongoose");
const axios = require("axios");

const app = express();
app.set("view engine", "ejs");
//------------------------------------------MIDDLEWARES----------------------------------------------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser(process.env.SESSION_SECRET));
// app.use(express.session());
app.use(fileUpload());
//CORS
app.use(
  cors({
    credentials: true, // allow session cookie from browser to pass through
    origin: "https://department-website.netlify.app/", // allow to server to accept request from different origin
    //methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  })
);

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// setting database connection
connection();

// making schema for mongoose user collection
const userSchema = new mongoose.Schema({
  name: String,
  username: String,
  password: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

// configuring passport.js
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//events schema and modeling
const eventSchema = new mongoose.Schema({
  title: String,
  type: String,
  info: {
    speaker: String,
    date: String,
    days: Number,
    timing: {
      from: String,
      to: String,
    },
  },
  description: String,
  link: String,
  imagePath: String,
});

const Event = mongoose.model("Event", eventSchema);

//news schema and modeling
const newsSchema = new mongoose.Schema({
  title: String,
  content: String,
  links: {
    filePath: String,
    webLink: String,
  },
  source: String,
  date: String,
});

const News = mongoose.model("New", newsSchema);

//---------------------------------------------ROUTES------------------------------------------------------------

// reset-passoword get route
app.get("/reset/:token", function (req, res) {
  User.findOne(
    {
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    },
    function (err, user) {
      if (!user) {
        console.log("error: Password reset token is invalid or has expired.");
        return res.send(
          '<h1 style="text-align: center;"> An error occured! Close this link and try again. </h1>'
        );
      }
      res.render("reset", {
        user: req.user,
      });
    }
  );
});

// logout get route
app.get("/api/logout", (req, res) => {
  req.logout();
  console.log("Succesfully logged out!");
  res.json({
    success: false,
    logout: true,
  });
});

// home get route
app.get("/api/home", (req, res) => {
  console.log(req.user);
  if (req.user) {
    res.json({
      success: true,
    });
  } else {
    res.json({
      success: false,
    });
  }
});

// events get route
app.get("/api/events", (req, res) => {
  Event.find((err, result) => {
    if (!err) {
      res.json(result);
    } else {
      res.json(err);
    }
  });
});

//news get routes
app.get("/api/news", (req, res) => {
  News.find((err, result) => {
    if (!err) {
      res.json(result);
    } else {
      res.json(err);
    }
  });
});

app.get("/api/news/:newsID", (req, res) => {
  News.findOne({ _id: req.params.newsID }, (err, result) => {
    if (!err) {
      res.json(result);
    } else {
      res.json(err);
    }
  });
});

//===================={POST Routes}=======================

// authentication post routes
app.post("/api/register", (req, res) => {
  User.register(
    new User({ name: req.body.name, username: req.body.username }),
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.json({
          success: false,
          error: err,
        });
      } else {
        passport.authenticate("local")(req, res, () => {
          console.log("Registered user : ", req.user);
          // res.redirect("/api/home");
          res.json({
            success: true,
            user: {
              name: req.user.name,
              username: req.user.username,
            },
          });
        });
      }
    }
  );
});

app.post("/api/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, (err) => {
    if (err) {
      console.log(err);
      res.json({
        success: false,
      });
    } else {
      passport.authenticate("local", function (err, user) {
        if (!user) {
          res.json({
            success: false,
          });
        } else {
          console.log("Logged in successfully!");
          // res.redirect("/api/home");
          res.json({
            success: true,
            user: {
              username: req.user.username,
            },
          });
        }
      })(req, res);
    }
  });
});

//change password route
app.post("/api/reset-password", function (req, res, next) {
  async.waterfall(
    [
      function (done) {
        crypto.randomBytes(20, function (err, buf) {
          var token = buf.toString("hex");
          done(err, token);
        });
      },
      function (token, done) {
        User.findOne({ username: req.body.username }, function (err, user) {
          if (!user) {
            console.log("error: No account with that email address exists.");
            return res.json({
              linkSent: false,
              msg: "No such account exits!",
            });
          }

          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 600000; // 10 minutes

          user.save(function (err) {
            done(err, token, user);
          });
        });
      },
      function (token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            user: process.env.MAIL_ID,
            pass: process.env.MAIL_PASSWORD,
          },
        });
        var mailOptions = {
          to: user.username,
          from: "dsccsadmin@passwordreset.com",
          subject: "DSC CS Admin Password Reset",
          text:
            "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
            "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
            "http://" +
            req.headers.host +
            "/reset/" +
            token +
            "\n\n" +
            "If you did not request this, please ignore this email and your password will remain unchanged.\n",
        };
        smtpTransport.sendMail(mailOptions, function (err) {
          console.log(
            "info: An e-mail has been sent to " +
              user.username +
              " with further instructions."
          );
          res.json({
            linkSent: true,
            msg: "Password reset link sent to your registered email!",
          });
          done(err, "done");
        });
      },
    ],
    function (err) {
      if (err) return next(err);
      res.json({
        linkSent: false,
        msg: "Error occured! Please try again later.",
      });
    }
  );
});

app.post("/reset/:token", function (req, res) {
  async.waterfall(
    [
      function (done) {
        User.findOne(
          {
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
          },
          function (err, user) {
            if (!user) {
              console.log(
                "error: Password reset token is invalid or has expired."
              );
              return res.send(
                '<h1 style="text-align: center;"> An error occured! Close this link and try again. </h1>'
              );
            }
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
            user.setPassword(req.body.password, function () {
              user.save((err) => {
                req.login(user, (err) => {
                  done(err, user);
                });
              });
              console.log("Password reset successful!");
            });
          }
        );
      },
      function (user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            user: process.env.MAIL_ID,
            pass: process.env.MAIL_PASSWORD,
          },
        });
        var mailOptions = {
          to: user.username,
          from: "dsccsadmin@passwordreset.com",
          subject: "Your password has been changed",
          text:
            "Hello,\n\n" +
            "This is a confirmation that the password for your account " +
            user.username +
            " has just been changed.\n",
        };
        smtpTransport.sendMail(mailOptions, function (err) {
          console.log("success: Success! Your password has been changed.");
          res.send(
            "<h2>Success! Your password has been changed. You may now continue your work.</h2>"
          );
          done(err);
        });
      },
    ],
    function (err) {
      res.send(
        '<h1 style="text-align: center;"> An error occured! Close this link and try again. </h1>'
      );
    }
  );
});

// events post route
app.post("/api/events", (req, res) => {
  if (!req.files) {
    return res.status(500).json({ msg: "Uploaded file not found" });
  }
  // accessing the file
  const myFile = req.files.file;
  myFile.mv(`${__dirname}/public/events/${myFile.name}`, function (err) {
    if (err) {
      console.log(err);
      // return res.status(500).json({ msg: "Error occured" });
    } else {
      console.log("Saved file on server successfully!");
    }
  });

  const newEvent = new Event({
    title: req.body.title,
    type: req.body.title,
    info: {
      speaker: req.body.speaker,
      date: new Date(req.body.date).toDateString(),
      days: req.body.days,
      timing: {
        from: req.body.timeFrom,
        to: req.body.timeTo,
      },
    },
    description: req.body.description,
    link: req.body.link,
    imagePath: `/events/${myFile.name}`,
  });

  newEvent.save((err) => {
    if (!err) {
      res.json({
        inserted: true,
        msg: "Added new event successfully",
      });
    } else {
      res.json({
        inserted: false,
        msg: "Error occured! Try again",
      });
    }
  });
});

// news post route
app.post("/api/news", (req, res) => {
  if (!req.files) {
    return res.status(500).json({ msg: "Uploaded file not found" });
  }
  // accessing the file
  const myFile = req.files.newFile;
  myFile.mv(`${__dirname}/public/news/${myFile.name}`, function (err) {
    if (err) {
      console.log(err);
      // return res.status(500).json({ msg: "Error occured" });
    } else {
      console.log("Saved file on server successfully!");
    }
  });
  const newNews = new News({
    title: req.body.title,
    content: req.body.content,
    links: {
      filePath: `/news/${myFile.name}`,
      webLink: req.body.link,
    },
    source: req.body.source,
    date: new Date(req.body.date).toDateString(),
  });

  newNews.save((err) => {
    if (!err) {
      res.json({
        inserted: true,
        msg: "Added new news successfully",
      });
    } else {
      res.json({
        inserted: false,
        msg: "Error occured! Try again",
      });
    }
  });
});

//-----------------------------------------listening to port------------------------------------------------------
const port = 5000 || process.env.PORT;
app.listen(port, () => {
  console.log("Server running on port " + port + "...");
});
