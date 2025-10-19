// src/routes/auth.routes.ts
import express from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate, authorize } from '../middleware/auth.middleware';
import { body } from 'express-validator';
import { validate } from '../middleware/validate.middleware';
import passport from '../config/passport';

const router = express.Router();
const authController = new AuthController();

// Validation rules
const registerValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('role').isIn(['patient', 'doctor']),
    body('fullName').notEmpty().trim(),
    validate
];

const loginValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
    validate
];

// Routes
router.post('/register', registerValidation, authController.register);
router.post('/login', loginValidation, authController.login);
router.post('/logout', authenticate, authController.logout);
router.post('/refresh-token', authController.refreshToken);
router.get('/verify-email/:token', authController.verifyEmail);

// 2FA routes
router.post('/2fa/setup', authenticate, authController.setup2FA);
router.post('/2fa/verify-setup', authenticate, authController.verify2FASetup);
router.post('/2fa/verify-login', authController.verify2FALogin);

// Google OAuth
router.get(
    '/google',
    passport.authenticate('google', { scope: ['profile', 'email'], session: false })
);

router.get(
    '/google/callback',
    passport.authenticate('google', { session: false, failureRedirect: '/login' }),
    (req, res) => {
        const result = req.user as any;

        // Set refresh token cookie
        res.cookie('refreshToken', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        // Redirect to frontend with access token
        res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${result.accessToken}`);
    }
);

// Protected route
router.get('/profile', authenticate, authController.getProfile);

export default router;