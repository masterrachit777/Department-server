require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const connection = require("./utils/db");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// setting database connection
connection();

// making schema for mongoose user collection
const userSchema = new mongoose.Schema({
    name: String,
    username: String,
    password: String
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

// configuring passport.js
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

// ROUTES
// app.get("/admin/login", (req, res) => {
//     res.sendFile(__dirname + "/login.html");
// })

// app.get("/admin/register", (req, res) => {
//     res.sendFile(__dirname + "/register.html");
// })

app.get("/admin/logout", (req, res) => {
    req.logout();
    res.send('Succesfully logged out!');
})

//POST Routes
app.post("/admin/register", (req, res) => {
    
    User.register(new User({ name: req.body.name, username: req.body.username}), req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.json({
                success: false,
                error: err
            });
        } else {
            passport.authenticate("local")(req, res, () => {

                console.log("Registered user : ", req.user);
                res.json({
                    success: true,
                    user: {
                        name: req.user.name,
                        username: req.user.username
                    }
                });
            });
        }
    });
});

app.post("/admin/login", (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err);
            res.json({
                success: false
            })
        } else {
            passport.authenticate("local")(req, res, () => {
                console.log("Logged in successfully!")
                res.json({
                    success: true,
                    user:{
                        username: req.user.username,
                        name: req.user.name
                    }
                });
            });
        }
    });
});

// listening to port
const port = 5000 || process.env.PORT;
app.listen(port, () => {
    console.log("Server running on port "+ port + "...");
})