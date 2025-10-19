import * as jwt from 'jsonwebtoken';

interface TokenPayload {
    userId: string;
    email: string;
    role: string;
}

const JWT_SECRET = process.env.JWT_SECRET || "secret";

export function generateAccessToken(payload: TokenPayload): string {
    return jwt.sign(payload, JWT_SECRET,
        {
            algorithm: 'RS256',
            expiresIn: '15m'
        },);
}

export function generateRefreshToken(payload: TokenPayload): string {
    return jwt.sign(payload, JWT_SECRET,
        {
            algorithm: 'RS256',
            expiresIn: '7d',
        },
    );
}

export function verifyAccessToken(token: string): TokenPayload {
    return jwt.verify(token, JWT_SECRET) as TokenPayload;
}

export function verifyRefreshToken(token: string): TokenPayload {
    return jwt.verify(token, JWT_SECRET) as TokenPayload;
}
