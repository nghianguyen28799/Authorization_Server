import config from "config"
import redisClient from "../utils/connectRedis";
import { signJwt } from "../utils/jwt";

export const signTokens = async (user: any) => {
    // 1. Create Session

    delete user.get().password

    redisClient.set(user.id, JSON.stringify(user), {
        EX: config.get<number>('redisCacheExpiresIn') * 60,
    });

    // 2. Create Access and Refresh tokens
    const access_token = signJwt({ sub: user.id }, 'JWT_ACCESS_TOKEN_PRIVATE_KEY', {
        expiresIn: `${config.get<number>('accessTokenExpiresIn')}m`,
    });

    const refresh_token = signJwt({ sub: user.id }, 'JWT_REFRESH_TOKEN_PRIVATE_KEY', {
        expiresIn: `${config.get<number>('refreshTokenExpiresIn')}m`,
    });

    return { access_token, refresh_token };
};