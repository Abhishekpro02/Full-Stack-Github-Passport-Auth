import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import passport from "passport";
import session from "express-session";
import path from "path";

import "./passport/github.auth.js";

import authRoutes from "./routes/auth.route.js";

import connectMongoDB from "./db/connectMongoDB.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const __dirname = path.resolve();

// cors policy for development
// app.use(
//   cors({
//     origin: "https://abhi-github-auth.vercel.app",
//     credentials: true,
//   })
// );
const oneWeek = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: oneWeek,
    },
  })
);
// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());

// Here we can remove the cors, it's not necessary in production because the frontend and backend are on the same domain. I forgot to mention that in the video, sorry about that.🙄
// app.use(cors());
// app.use(express.json());
// app.use(express.urlencoded({ extended: true }));

app.use("/api/auth", authRoutes);

app.use(express.static(path.join(__dirname, "/frontend/dist")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "dist", "index.html"));
});
app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
  connectMongoDB();
});
