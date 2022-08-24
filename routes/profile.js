const express = require("express");
const router = express.Router();
const { pool } = require("../db/dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const initializePassport = require("../passport/passportConfig");
initializePassport(passport);

router.get("/login", checkAuthenticated, (req, res) => {
  res.render("login");
});

router.get("/register", checkAuthenticated, (req, res) => {
  res.render("register");
});

router.get("/test", checkNotAuthenticated, (req, res) => {
  res.render("test", { user: req.user.name });
});

router.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      throw err;
    }

    req.flash("success_msg", "You have logged out");
    res.redirect("/app/login");
  });
});

router.post("/register", async (req, res) => {
  let { name, email, password, password2 } = req.body;

  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({ message: "Please enter all fields" });
  }

  if (password.length < 6) {
    errors.push({ message: "Password should be at least 6 characters" });
  }

  if (password != password2) {
    errors.push({ message: "Passwords do not match" });
  }

  if (errors.length > 0) {
    res.render("register", { errors });
  } else {
    // Form validation passed
    let hashedPassword = await bcrypt.hash(password, 10);

    pool.query(
      `SELECT * FROM users
          WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          throw err;
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          errors.push({ message: "Email already registered" });
          res.render("register", { errors });
        } else {
          pool.query(
            `INSERT INTO users (name, email, password)
                  VALUES ($1, $2, $3)
                  RETURNING id, password`,
            [name, email, hashedPassword],
            (err, results) => {
              if (err) {
                throw err;
              }
              console.log(results.rows);
              req.flash("success_msg", "You are now registered. Please log in");
              res.redirect("/app/login");
            }
          );
        }
      }
    );
  }
});

router.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/app/test",
    failureRedirect: "/app/login",
    failureFlash: true,
  })
);

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/app/login");
}

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/app/test");
  }
  next();
}

module.exports = router;
