import passport from "passport";
import dotenv from "dotenv";
import { Strategy as GitHubStrategy } from "passport-github2";
import User from "../models/user.model.js";

dotenv.config();

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (obj, done) {
  done(null, obj);
});

// Use the GitHubStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and GitHub
//   profile), and invoke a callback with a user object.
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL:
        "https://full-stack-github-passport-auth.onrender.com/api/auth/github/callback",
    },
    async function (accessToken, refreshToken, profile, done) {
      const user = await User.findOne({ username: profile.username });

      // modify access token to be stored in the database.
      // accessToken is the token we get from the github api when the user logs in.

      // login
      if (user) {
        user.accessToken = accessToken;
        await user.save({
          validateBeforeSave: false,
        });
        done(null, user);
      }

      // signup
      if (!user) {
        const newUser = new User({
          name: profile.displayName,
          username: profile.username,
          profileUrl: profile.profileUrl,
          avatarUrl: profile.photos[0].value,
          accessToken: accessToken,
        });
        await newUser.save();
        done(null, newUser);
      } else {
        done(null, user);
      }
    }
  )
);
