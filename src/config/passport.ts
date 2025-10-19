// src/config/passport.ts
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { AuthService } from '../services/auth.services';

const authService = new AuthService();

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID!,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
            callbackURL: process.env.GOOGLE_CALLBACK_URL!
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const result = await authService.googleAuth(profile);
                return done(null, result);
            } catch (error) {
                return done(error, undefined);
            }
        }
    )
);

export default passport;