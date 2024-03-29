import express from "express";
import passport from "passport";
import isAuthenticated from "../middlewares/auth.middleware.js";

const router = express.Router();

router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

router.get(
  "/github/callback",
  passport.authenticate("github", {
    failureRedirect: process.env.CLIENT_BASE_URL + "/login",
  }),
  function (req, res) {
    res.redirect(process.env.CLIENT_BASE_URL + "/profile");
  }
);

router.get("/check", (req, res) => {
  if (req.isAuthenticated()) {
    res.send({ user: req.user });
  } else {
    res.send({ user: null });
  }
});

router.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    res.json({ message: "Logged out" });
  });
});

//get auth user profile
router.get("/profile", isAuthenticated, (req, res) => {
  res.status(200).json({
    user: req.user,
    success: true,
    message: "User profile",
  });
});

export default router;
