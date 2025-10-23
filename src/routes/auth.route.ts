// src/routes/auth.routes.ts
import express from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';
import { body } from 'express-validator';
import { validate } from '../middleware/validate.middleware';
import passport from '../config/passport';

const router = express.Router();
const authController = new AuthController();

// Validation rules
const registerValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('role').isIn(['patient', 'doctor']),
    body('fullName').notEmpty().trim(),
    validate,
];

const loginValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
    validate,
];

// Public routes
router.post('/register', registerValidation, authController.register.bind(authController));
router.post('/login', loginValidation, authController.login.bind(authController));
router.get('/verify-email/:token', authController.verifyEmail.bind(authController));
router.post('/resend-verification', authController.resendVerificationEmail.bind(authController));

// 2FA routes
router.post('/2fa/verify-login', authController.verify2FALogin.bind(authController));

// Protected routes
router.use(authenticate); // All routes below require authentication

router.get('/profile', authController.getProfile.bind(authController));
router.post('/refresh-token', authController.refreshToken.bind(authController));
router.post('/logout', authController.logout.bind(authController));
router.post('/logout-all', authController.logoutAllDevices.bind(authController));

// 2FA setup (protected)
router.post('/2fa/setup', authController.setup2FA.bind(authController));
router.post('/2fa/verify-setup', authController.verify2FASetup.bind(authController));
router.post('/2fa/disable', authController.disable2FA.bind(authController));

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
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        // Redirect to frontend with access token
        res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${result.accessToken}`);
    }
);

export default router;