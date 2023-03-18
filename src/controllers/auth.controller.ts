import { Request, Response, CookieOptions, NextFunction } from "express";
import config from 'config';
import { CreateUserInput, LoginUserInput } from "../schemas/user.schema";
import AppError from "../utils/appError";
import { signTokens } from "../services/auth.service";
import { signJwt, verifyJwt } from "../utils/jwt";
import redisClient from "../utils/connectRedis";
import { findUserByEmail, findUserByPk, registerUserService } from "../services/user.service";

const cookiesOptions: CookieOptions = {
    httpOnly: true,
    sameSite: 'lax',
};

if (process.env.NODE_ENV === 'production') cookiesOptions.secure = true;

const accessTokenCookieOptions: CookieOptions = {
    ...cookiesOptions,
    expires: new Date(
        Date.now() + config.get<number>('accessTokenExpiresIn') * 60 * 1000
    ),
    maxAge: config.get<number>('accessTokenExpiresIn') * 60 * 1000,
};

const refreshTokenCookieOptions: CookieOptions = {
    ...cookiesOptions,
    expires: new Date(
        Date.now() + config.get<number>('refreshTokenExpiresIn') * 60 * 1000
    ),
    maxAge: config.get<number>('refreshTokenExpiresIn') * 60 * 1000,
};

export const registerUserController = async (req: Request<{}, {}, CreateUserInput>, res: Response, next: NextFunction) => {
    try {
        const user = await registerUserService(req.body)

        res.status(201).json({
            status: "success",
            data: {
                user,
            },
        });
    } catch (err: any) {
        if (err.parent.code === '23505') {
            return res.status(409).json({
                status: 'fail',
                message: 'User with that email already exist',
            });
        }
        next(err);
    }
}

export const loginUserController = async (req: Request<{}, {}, LoginUserInput>, res: Response, next: NextFunction) => {
    try {
        const { email, password } = req.body;

        const user = await findUserByEmail(email);

        if (!user || !(await user.comparePassword(password, user.password))) {
            next(new AppError(400, 'Invalid email or password'));
        }

        const { access_token, refresh_token } = await signTokens(user)

        res.cookie('access_token', access_token, accessTokenCookieOptions);
        res.cookie('refresh_token', refresh_token, refreshTokenCookieOptions);

        res.cookie('logged_in', true, {
            ...accessTokenCookieOptions,
            httpOnly: false,
        });

        res.status(200).json({
            status: 'success',
            access_token
        })
    } catch (err) {
        next(err);
    }
}

export const refreshTokenController = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { refresh_token } = req.cookies;

        const message = "Could not refresh access token"
        if (!refresh_token) {
            return next(new AppError(403, message))
        }

        const decoded = verifyJwt<{ sub: string }>(
            refresh_token,
            'JWT_REFRESH_TOKEN_PUBLIC_KEY'
        )

        if (!decoded) {
            return next(new AppError(403, message))
        }

        const session = await redisClient.get(decoded.sub)

        if (!session) {
            return next(new AppError(403, message))
        }

        const user = await findUserByPk(JSON.parse(session).id);

        if (!user) {
            return next(new AppError(403, message))
        }

        const access_token = signJwt({ sub: user.id }, "JWT_ACCESS_TOKEN_PRIVATE_KEY", {
            expiresIn: `${config.get<number>("accessTokenExpiresIn")}m`
        })

        res.cookie('access_token', access_token, accessTokenCookieOptions);
        res.cookie('logged_in', true, {
            ...accessTokenCookieOptions,
            httpOnly: false,
        })

        res.status(200).json({
            status: 'success',
            access_token
        })
    } catch (err) {
        next(err)
    }
}

export const logout = (res: Response) => {
    res.cookie('access_token', '', { maxAge: -1 });
    res.cookie('refresh_token', '', { maxAge: -1 });
    res.cookie('logged_in', '', { maxAge: -1 });
}

export const logoutController = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = res.locals.user;

        await redisClient.del(user.id);
        logout(res);

        res.status(200).json({
            status: 'success',
        })
    } catch (err: any) {
        next(err);
    }
}