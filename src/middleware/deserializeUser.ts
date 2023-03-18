import { NextFunction, Request, Response } from 'express';
import AppError from '../utils/appError';
import redisClient from '../utils/connectRedis';
import { verifyJwt } from '../utils/jwt';
import UserModel from '../models/user.model';

export const deserializeUser = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        let access_token;

        if (
            req.headers.authorization &&
            req.headers.authorization.startsWith('Bearer')
        ) {
            access_token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies.access_token) {
            access_token = req.cookies.access_token;
        }

        if (!access_token) {
            return next(new AppError(401, 'You are not logged in'));
        }


        // Validate the access token
        const decoded = verifyJwt<{ sub: string }>(
            access_token,
            'JWT_ACCESS_TOKEN_PUBLIC_KEY'
        );

        if (!decoded) {
            return next(new AppError(401, `Invalid token or user doesn't exist`));
        }

        console.log(decoded);

        // Check if the user has a valid session
        const session = await redisClient.get(decoded.sub);


        if (!session) {
            return next(new AppError(401, `Invalid token or session has expired`));
        }

        // Check if the user still exist

        // const user = await UserModel.findByPk(JSON.parse(session).id, {
        //     attributes: {
        //         exclude: ['password']
        //     }
        // });
        const user = JSON.parse(session);

        if (!user) {
            return next(new AppError(401, `Invalid token or session has expired`));
        }

        // Add user to res.locals
        res.locals.user = user;

        next();
    } catch (err: any) {
        next(err);
    }
};

