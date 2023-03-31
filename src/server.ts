import express, { NextFunction, Request, Response } from "express";
import morgan from "morgan";
import router from "./routes/index"
import cors from "cors";
import { connectDB, sequelize } from "./utils/connectDB";
import AppError from "./utils/appError";
import config from 'config';
import passport from 'passport';
import cookieSession from 'cookie-session'

require("dotenv").config();

const app = express();

app.use(express.json({ limit: "10kb" }));
if (process.env.NODE_ENV === "development") app.use(morgan("dev"));

app.use(cookieSession({
  name: 'session',
  keys: ["googleauthen"],
  maxAge: config.get<number>('accessTokenExpiresIn') * 60 * 1000
}))

app.use(passport.initialize());
app.use(passport.session());

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN as unknown as string;
app.use(
  cors({
    origin: [FRONTEND_ORIGIN],
    methods: "GET, POST PUT, DELETE",
    credentials: true,
  })
);

const { UserRouter, AuthRouter } = router;

app.get("/api/healthchecker", (req: Request, res: Response) => {
  res.status(200).json({
    status: "success",
    message: "Build CRUD API with Node.js and Sequelize",
  });
});

app.use('/api/auth', AuthRouter);
app.use('/api/user', UserRouter);

app.all("*", (req: Request, res: Response) => {
  res.status(400).json({
    status: "fail",
    message: `Route: ${req.originalUrl} dose not exists on this server`,
  });
});

app.use(
  (error: AppError, req: Request, res: Response, next: NextFunction) => {
    error.status = error.status || 'error';
    error.statusCode = error.statusCode || 500;

    res.status(error.statusCode).json({
      status: error.status,
      message: error.message,
    });
  }
);

const PORT = process.env.PORT || 8000;

app.listen(PORT, async () => {
  console.log("🚀Server started Successfully");
  await connectDB();
  sequelize.sync({ force: false }).then(() => {
    console.log("✅Synced database successfully...");
  });
});