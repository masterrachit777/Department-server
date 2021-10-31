require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const connection = require("./utils/db");
const session = require("express-session");
const cors = require("cors");
const passport = require("passport");
const cookieParser = require("cookie-parser");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

//------------------------------------------MIDDLEWARES----------------------------------------------------------
app.use(express.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(cookieParser());
//CORS
app.use(cors({
    credentials: true, // allow session cookie from browser to pass through
    origin: "http://localhost:3000" // allow to server to accept request from different origin
    //methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
}));

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

passport.serializeUser(User.serializeUser());  
passport.deserializeUser(User.deserializeUser());

//---------------------------------------------ROUTES------------------------------------------------------------
app.get("/api/logout", (req, res) => {
    req.logout();
    console.log('Succesfully logged out!');
    res.json({
        success: false,
        logout: true
    })
});

app.get("/api/home", (req, res) => {

    console.log(req.user);
    if(req.user){
        res.json({
            success: true
        })
    } else {
        res.json({
            success: false
        })
    }
});

//POST Routes
app.post("/api/register", (req, res) => {
    
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
                // res.redirect("/api/home");
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

app.post("/api/login", (req, res) => {

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
            passport.authenticate("local", function(err, user){
                if(!user) {
                    res.json({
                        success: false
                    });
                } else {
                    console.log("Logged in successfully!")
                    // res.redirect("/api/home");
                    res.json({
                        success: true,
                        user:{
                            username: req.user.username,
                        }
                    });
                }
            })(req, res);
        }
    });
});


//-----------------------------------------listening to port------------------------------------------------------
const port = 5000 || process.env.PORT;
app.listen(port, () => {
    console.log("Server running on port "+ port + "...");
})