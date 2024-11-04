let express = require("express");
let router = express.Router();
let userController = require("../controllers/userController");
const jwt = require("jsonwebtoken");

const { checkSchema } = require("express-validator");

const createUserValidationSchema = require("./utils/userValidationSchemas");
const userLoginValidationSchema = require("./utils/userLoginValidationSchemas");
const auth = require("./auth");

router.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

/* GET home page. */
router.get("/", function (req, res, next) {
  res.render("index", { errors: null });
});

router.get("/sign-up", (req, res) => {
  res.render("sign-up", { errors: null });
});
router.get("/log-in", (req, res) => {
  res.render("index/log-in", { errors: null });
});

router.post(
  "/sign-up",
  checkSchema(createUserValidationSchema),
  userController.handleUserSignUp,
  auth.passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

router.post(
  "/log-in",
  checkSchema(userLoginValidationSchema),
  userController.handleUserLogIn,
  userController.handleUserAuthentication
);

router.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// FORMAT OF TOKEN
// Authorization: Bearer <access_token>

// Verify token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];
  console.log(bearerHeader);

  // Check if bearer is undefined
  if (typeof bearerHeader !== "undefined") {
    // Split at the space
    const bearer = bearerHeader.split(" ");
    // Get the token from Array
    const bearerToken = bearer[1];

    // Set the token
    req.token = bearerToken;

    // Call the next middleware
    next();
  } else {
    // Forbidden
    res.sendStatus(403);
  }
}
module.exports = router;
