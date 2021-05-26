//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const app = express();

app.set("view engine", "ejs");

app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(express.static("public"));
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.set("useCreateIndex", true);
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

const userschema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});
userschema.plugin(passportLocalMongoose);
userschema.plugin(findOrCreate);
// userschema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ["password"],
// });
const User = mongoose.model("User", userschema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);
app.get("/", function (req, res) {
  res.render("home");
});
app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, found) {
    if (!err) {
      if (found) {
        res.render("secrets", {
          foundusers: found,
        });
      }
    }
  });
});
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/logout", function (req, res) {
  req.logOut();
  res.redirect("/home");
});
app
  .route("/login")
  .get(function (req, res) {
    res.render("login");
  })
  .post(function (req, res) {
    const user = new User({
      email: req.body.username,
      password: req.body.password,
    });
    req.login(user, function (err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    });

    // User.findOne({ email: req.body.username }, function (err, found) {
    //   if (!err) {
    //     if (found) {
    //       bcrypt.compare(
    //         req.body.password,
    //         found.password,
    //         function (err, result) {
    //           if (result == true) {
    //             res.render();
    //           }
    //         }
    //       );
    //     } else {
    //       console.log("No such user");
    //     }
    //   } else {
    //     console.log(err);
    //   }
    // });
  });

app
  .route("/register")
  .get(function (req, res) {
    res.render("register");
  })
  .post(function (req, res) {
    User.register(
      { username: req.body.username },
      req.body.password,
      function (err, user) {
        if (err) {
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );

    // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    //   const newuser = new User({
    //     email: req.body.username,
    //     password: hash,
    //   });
    //   newuser.save(function (err) {
    //     if (!err) {
    //       res.render("secrets");
    //     }
    //   });
    // });
  });

app
  .route("/submit")
  .get(function (req, res) {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  })
  .post(function (req, res) {
    User.findById(req.user.id, function (err, found) {
      if (!err) {
        found.secret = req.body.secret;
        found.save(function (err) {
          if (!err) {
            res.redirect("/secrets");
          }
        });
      }
    });
  });
app.listen(3000, function () {
  console.log("Server started on port 3000");
});
