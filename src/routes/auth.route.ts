import express from "express";
import { validate } from "../middleware/validate";
import { createUserSchema, loginUserSchema } from "../schemas/user.schema";
import { loginUserController, logoutController, refreshTokenController, registerUserController } from "../controllers/auth.controller";
import { deserializeUser } from "../middleware/deserializeUser";
import { requireUser } from "../middleware/requireUser";

const router = express.Router();

router.route("/register")
    .post(validate(createUserSchema), registerUserController)

router.route('/login').post(validate(loginUserSchema), loginUserController)

router.route('/logout').get(deserializeUser, requireUser, logoutController)

router.route('/refresh_token').get(refreshTokenController)
export default router