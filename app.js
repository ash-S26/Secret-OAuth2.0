// Here some addition to previous version that is with session and cookie are
// Login with google, secret in .env file .

// oauth2 = Open Authorisation
// It allows us to fetch data of users from sites which user uses that
// allow to use that data maybe to suggest them to follow their friends
// if user's friends are on our app, or to use data from other site to fill
// data required on our site. Basically we use/request there data on other websites
// like google,facebook,etc to our site so we can use their data.
// Also we can get data like friends,emails,liked items,etc.
// Also by using Oauth we don't need to deal with security of user credentials
// like storing them securly,hashing salting and don't need to
// worry of getting hacked as everything is handles bu Oauth site like
// google, facebook , twitter , etc .

// Once user click on Sign in with google we will redirect them to google
// login where they authenticate with their google account and then google
// will send us Auth code , we can then also exchange auth code for access
// token so we can sebsequently retrive data.

// Auth Code is like one time use , like a ticket of movie.
// Access Token have long time usability and we can store this in our
// database and use anytime we need to retrive or access user's data.

// Configure to use environment variables.
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
// importing google Oauth statergy
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true});
mongoose.set('strictQuery', false);

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
//  Plugin to use findOrCreate pakage with our database.
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// Below serialization and Deserialization from passport works for any statergy
// and not just local (as earlier method used method that uses passportLocalMongoose which was just for local statergy).
// Now we can use any statergy like google,facebook,etc .
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Make passport to use GoogleStrategy for authentication
// Passport depenends on user's google+ account for retriving data but google+
// is closing soon so to avoid breaking of application we provide additional
// property userProfileURL which gives new endpoint to look for user's information
// on google to passport.
// This is google statergy configuration.
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  // Callback function sending us various data, profile have email,googleid.
  function(accessToken, refreshToken, profile, cb) {

    // This finds a user with googleId and not local DB Id in our database if not exist
    // then create user with that id and email.
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

// When user clicks on button Sign up or Sign in with google we use passport
// to authenticate user and make passport use statergy "google" instead of local
// and scope is data for user that we want which is profile(that have their email and id)
// of user.
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

// This route is hit after the google has authenticated user and redirect them here
// so we can then authenticate them locally by creating session cookie if Successful
// and render secrets page. But if failed in google authentication we redirect them
// to "/login" route .
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

// Secrets page
app.get("/secrets", function(req, res){
  // Look through collection entries and find where secret field is not null
  // that is user have a secret.
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

// Route when user wants to submit a secret .
app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout(function (err) {
    if(err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});







app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
