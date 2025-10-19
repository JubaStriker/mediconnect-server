// src/services/auth.service.ts
import pool from '../config/database';
import redisClient from '../config/redis';
import { hashPassword, comparePassword } from '../utils/password.utils';
import { generateAccessToken, generateRefreshToken } from '../utils/jwt.utils';
import crypto from 'crypto';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import * as jwt from 'jsonwebtoken';

export interface RegisterUserDto {
    email: string;
    password: string;
    role: 'patient' | 'doctor';
    fullName: string;
    phone?: string;
    // Doctor specific
    specialization?: string;
    licenseNumber?: string;
    // Patient specific
    dateOfBirth?: string;
    gender?: string;
}

export class AuthService {
    // Register new user
    async register(data: RegisterUserDto) {
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            // Check if user exists
            const existingUser = await client.query(
                'SELECT id FROM users WHERE email = $1',
                [data.email]
            );

            if (existingUser.rows.length > 0) {
                throw new Error('Email already registered');
            }

            // Hash password
            const passwordHash = await hashPassword(data.password);

            // Create user
            const userResult = await client.query(
                `INSERT INTO users (email, password_hash, role) 
         VALUES ($1, $2, $3) 
         RETURNING id, email, role, created_at`,
                [data.email, passwordHash, data.role]
            );

            const user = userResult.rows[0];

            // Create profile based on role
            if (data.role === 'doctor') {
                await client.query(
                    `INSERT INTO doctor_profiles (user_id, full_name, specialization, license_number, phone) 
           VALUES ($1, $2, $3, $4, $5)`,
                    [user.id, data.fullName, data.specialization, data.licenseNumber, data.phone]
                );
            } else {
                await client.query(
                    `INSERT INTO patient_profiles (user_id, full_name, phone, date_of_birth, gender) 
           VALUES ($1, $2, $3, $4, $5)`,
                    [user.id, data.fullName, data.phone, data.dateOfBirth || null, data.gender || null]
                );
            }

            // Generate email verification token
            const verificationToken = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

            await client.query(
                `INSERT INTO email_verification_tokens (user_id, token, expires_at) 
         VALUES ($1, $2, $3)`,
                [user.id, verificationToken, expiresAt]
            );

            await client.query('COMMIT');

            // TODO: Send verification email
            // await emailService.sendVerificationEmail(user.email, verificationToken);

            return {
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role
                },
                message: 'Registration successful. Please check your email to verify your account.'
            };
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    // Login with email and password
    async login(email: string, password: string) {
        // Get user
        const userResult = await pool.query(
            `SELECT id, email, password_hash, role, is_email_verified, is_active, two_factor_enabled 
       FROM users WHERE email = $1`,
            [email]
        );

        if (userResult.rows.length === 0) {
            throw new Error('Invalid credentials');
        }

        const user = userResult.rows[0];

        // Check if account is active
        if (!user.is_active) {
            throw new Error('Account is deactivated');
        }

        // Verify password
        const isValidPassword = await comparePassword(password, user.password_hash);
        if (!isValidPassword) {
            throw new Error('Invalid credentials');
        }

        // Check email verification
        if (!user.is_email_verified) {
            throw new Error('Please verify your email first');
        }

        // If 2FA is enabled, return a temp token
        if (user.two_factor_enabled) {
            const tempToken = crypto.randomBytes(32).toString('hex');

            // Store temp token in Redis (expires in 5 minutes)
            await redisClient.setEx(
                `2fa:${tempToken}`,
                300,
                JSON.stringify({ userId: user.id, email: user.email, role: user.role })
            );

            return {
                requiresTwoFactor: true,
                tempToken,
                message: 'Please enter your 2FA code'
            };
        }

        // Generate tokens
        const accessToken = generateAccessToken({
            userId: user.id,
            email: user.email,
            role: user.role
        });

        const refreshToken = generateRefreshToken({
            userId: user.id,
            email: user.email,
            role: user.role
        });

        // Store refresh token
        const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        await pool.query(
            `INSERT INTO refresh_tokens (user_id, token, expires_at) 
       VALUES ($1, $2, $3)`,
            [user.id, refreshToken, refreshExpiresAt]
        );

        return {
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                email: user.email,
                role: user.role
            }
        };
    }

    // Setup 2FA
    async setup2FA(userId: string) {
        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `${process.env.TWO_FACTOR_ISSUER} (${userId})`,
            length: 32
        });

        // Store secret temporarily in Redis (expires in 10 minutes)
        await redisClient.setEx(
            `2fa-setup:${userId}`,
            600,
            secret.base32
        );

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);

        return {
            secret: secret.base32,
            qrCode: qrCodeUrl,
            message: 'Scan this QR code with your authenticator app'
        };
    }

    // Verify and enable 2FA
    async verify2FASetup(userId: string, token: string) {
        // Get secret from Redis
        const secret = await redisClient.get(`2fa-setup:${userId}`);

        if (!secret) {
            throw new Error('2FA setup session expired. Please start again.');
        }

        // Verify token
        const isValid = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token,
            window: 2
        });

        if (!isValid) {
            throw new Error('Invalid 2FA code');
        }

        // Save secret to database and enable 2FA
        await pool.query(
            `UPDATE users 
       SET two_factor_secret = $1, two_factor_enabled = true 
       WHERE id = $2`,
            [secret, userId]
        );

        // Delete temp secret from Redis
        await redisClient.del(`2fa-setup:${userId}`);

        return {
            message: '2FA enabled successfully'
        };
    }

    // Verify 2FA during login
    async verify2FALogin(tempToken: string, token: string) {
        // Get user data from Redis
        const userData = await redisClient.get(`2fa:${tempToken}`);

        if (!userData) {
            throw new Error('Invalid or expired session');
        }

        const { userId, email, role } = JSON.parse(userData);

        // Get user's 2FA secret
        const userResult = await pool.query(
            'SELECT two_factor_secret FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            throw new Error('User not found');
        }

        const { two_factor_secret } = userResult.rows[0];

        // Verify token
        const isValid = speakeasy.totp.verify({
            secret: two_factor_secret,
            encoding: 'base32',
            token,
            window: 2
        });

        if (!isValid) {
            throw new Error('Invalid 2FA code');
        }

        // Delete temp token
        await redisClient.del(`2fa:${tempToken}`);

        // Generate tokens
        const accessToken = generateAccessToken({ userId, email, role });
        const refreshToken = generateRefreshToken({ userId, email, role });

        // Store refresh token
        const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        await pool.query(
            `INSERT INTO refresh_tokens (user_id, token, expires_at) 
       VALUES ($1, $2, $3)`,
            [userId, refreshToken, refreshExpiresAt]
        );

        return {
            accessToken,
            refreshToken,
            user: { id: userId, email, role }
        };
    }

    // Verify email
    async verifyEmail(token: string) {
        const result = await pool.query(
            `SELECT user_id, expires_at FROM email_verification_tokens 
       WHERE token = $1`,
            [token]
        );

        if (result.rows.length === 0) {
            throw new Error('Invalid verification token');
        }

        const { user_id, expires_at } = result.rows[0];

        if (new Date() > new Date(expires_at)) {
            throw new Error('Verification token expired');
        }

        // Update user
        await pool.query(
            'UPDATE users SET is_email_verified = true WHERE id = $1',
            [user_id]
        );

        // Delete token
        await pool.query(
            'DELETE FROM email_verification_tokens WHERE token = $1',
            [token]
        );

        return { message: 'Email verified successfully' };
    }

    // Google OAuth login/register
    async googleAuth(profile: any) {
        const { id: googleId, emails, displayName } = profile;
        const email = emails[0].value;

        // Check if user exists
        let userResult = await pool.query(
            'SELECT id, email, role, is_active FROM users WHERE google_id = $1 OR email = $2',
            [googleId, email]
        );

        let user;

        if (userResult.rows.length === 0) {
            // Create new user
            const client = await pool.connect();
            try {
                await client.query('BEGIN');

                const newUserResult = await client.query(
                    `INSERT INTO users (email, google_id, role, is_email_verified) 
           VALUES ($1, $2, 'patient', true) 
           RETURNING id, email, role`,
                    [email, googleId]
                );

                user = newUserResult.rows[0];

                // Create patient profile
                await client.query(
                    `INSERT INTO patient_profiles (user_id, full_name) 
           VALUES ($1, $2)`,
                    [user.id, displayName]
                );

                await client.query('COMMIT');
            } catch (error) {
                await client.query('ROLLBACK');
                throw error;
            } finally {
                client.release();
            }
        } else {
            user = userResult.rows[0];

            // Update google_id if not set
            if (!user.google_id) {
                await pool.query(
                    'UPDATE users SET google_id = $1 WHERE id = $2',
                    [googleId, user.id]
                );
            }
        }

        // Check if active
        if (!user.is_active) {
            throw new Error('Account is deactivated');
        }

        // Generate tokens
        const accessToken = generateAccessToken({
            userId: user.id,
            email: user.email,
            role: user.role
        });

        const refreshToken = generateRefreshToken({
            userId: user.id,
            email: user.email,
            role: user.role
        });

        // Store refresh token
        const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        await pool.query(
            `INSERT INTO refresh_tokens (user_id, token, expires_at) 
       VALUES ($1, $2, $3)`,
            [user.id, refreshToken, refreshExpiresAt]
        );

        return {
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                email: user.email,
                role: user.role
            }
        };
    }

    // Refresh access token
    async refreshAccessToken(refreshToken: string) {
        // Verify refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!);

        // Check if token exists in database
        const result = await pool.query(
            `SELECT user_id FROM refresh_tokens 
       WHERE token = $1 AND expires_at > NOW()`,
            [refreshToken]
        );

        if (result.rows.length === 0) {
            throw new Error('Invalid refresh token');
        }

        // Generate new access token
        // const accessToken = generateAccessToken({
        //     userId: result?.userId || '',
        //     email: result?.email,
        //     role: result?.role
        // });

        return { accessToken: 'testToken' };
    }

    // Logout
    async logout(refreshToken: string) {
        await pool.query(
            'DELETE FROM refresh_tokens WHERE token = $1',
            [refreshToken]
        );

        return { message: 'Logged out successfully' };
    }
}