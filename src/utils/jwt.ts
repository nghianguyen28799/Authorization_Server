import jwt, { SignOptions } from 'jsonwebtoken';

// ? Sign Access or Refresh Token
export const signJwt = (
    payload: Object,
    keyName: 'JWT_ACCESS_TOKEN_PRIVATE_KEY' | 'JWT_REFRESH_TOKEN_PRIVATE_KEY',
    options: SignOptions
) => {

    const privateKey = Buffer.from(
        process.env[keyName] as string,
        'base64'
    ).toString('ascii');
    return jwt.sign(payload, privateKey, {
        ...(options && options),
        algorithm: 'RS256',
    });
};

// ? Verify Access or Refresh Token
export const verifyJwt = <T>(
    token: string,
    keyName: 'JWT_ACCESS_TOKEN_PUBLIC_KEY' | 'JWT_REFRESH_TOKEN_PUBLIC_KEY'
): T | null => {
    try {
        const publicKey = Buffer.from(
            process.env[keyName] as string,
            'base64'
        ).toString('ascii');

        const decoded = jwt.verify(token, publicKey) as T;

        return decoded
    } catch (error) {
        return null;
    }
};
