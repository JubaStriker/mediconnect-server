// src/services/auth.service.ts
import { Role } from '@prisma/client';
import prisma from '../lib/prisma';
import redisClient from '../config/redis';
import { hashPassword, comparePassword } from '../utils/password.utils';
import { generateAccessToken, generateRefreshToken } from '../utils/jwt.utils';
import crypto from 'crypto';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

export interface RegisterUserDto {
    email: string;
    password: string;
    role: 'patient' | 'doctor';
    fullName: string;
    phone?: string;
    // Doctor specific
    specialization?: string;
    licenseNumber?: string;
    experienceYears?: number;
    consultationFee?: number;
    bio?: string;
    // Patient specific
    dateOfBirth?: string;
    gender?: string;
    bloodGroup?: string;
    address?: string;
    emergencyContact?: string;
}

export class AuthService {
    /**
     * Register a new user (patient or doctor)
     */
    async register(data: RegisterUserDto) {
        try {
            // Check if user already exists
            const existingUser = await prisma.user.findUnique({
                where: { email: data.email.toLowerCase() },
            });

            if (existingUser) {
                throw new Error('Email already registered');
            }

            // Hash password
            const passwordHash = await hashPassword(data.password);

            // Create user with profile in a transaction
            const user = await prisma.$transaction(async (tx) => {
                // Create user
                const newUser = await tx.user.create({
                    data: {
                        email: data.email.toLowerCase(),
                        passwordHash,
                        role: data.role as Role,
                    },
                });

                // Create profile based on role
                if (data.role === 'doctor') {
                    if (!data.specialization || !data.licenseNumber) {
                        throw new Error('Specialization and license number are required for doctors');
                    }

                    await tx.doctorProfile.create({
                        data: {
                            userId: newUser.id,
                            fullName: data.fullName,
                            specialization: data.specialization,
                            licenseNumber: data.licenseNumber,
                            experienceYears: data.experienceYears,
                            consultationFee: data.consultationFee,
                            bio: data.bio,
                            phone: data.phone,
                        },
                    });
                } else if (data.role === 'patient') {
                    await tx.patientProfile.create({
                        data: {
                            userId: newUser.id,
                            fullName: data.fullName,
                            phone: data.phone,
                            dateOfBirth: data.dateOfBirth ? new Date(data.dateOfBirth) : null,
                            gender: data.gender,
                            bloodGroup: data.bloodGroup,
                            address: data.address,
                            emergencyContact: data.emergencyContact,
                        },
                    });
                }

                // Generate email verification token
                const verificationToken = crypto.randomBytes(32).toString('hex');
                const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

                await tx.emailVerificationToken.create({
                    data: {
                        userId: newUser.id,
                        token: verificationToken,
                        expiresAt,
                    },
                });

                return { user: newUser, verificationToken };
            });

            // TODO: Send verification email
            console.log(`📧 Verification token: ${user.verificationToken}`);

            return {
                user: {
                    id: user.user.id,
                    email: user.user.email,
                    role: user.user.role,
                },
                message: 'Registration successful. Please check your email to verify your account.',
            };
        } catch (error: any) {
            console.error('Registration error:', error);
            throw error;
        }
    }

    /**
     * Login with email and password
     */
    async login(email: string, password: string) {
        try {
            // Find user
            const user = await prisma.user.findUnique({
                where: { email: email.toLowerCase() },
            });

            if (!user || !user.passwordHash) {
                throw new Error('Invalid credentials');
            }

            // Check if account is active
            if (!user.isActive) {
                throw new Error('Account is deactivated');
            }

            // Verify password
            const isValidPassword = await comparePassword(password, user.passwordHash);
            if (!isValidPassword) {
                throw new Error('Invalid credentials');
            }

            // Check email verification
            if (!user.isEmailVerified) {
                throw new Error('Please verify your email first');
            }

            // If 2FA is enabled, return temp token
            if (user.twoFactorEnabled) {
                const tempToken = crypto.randomBytes(32).toString('hex');

                await redisClient.setEx(
                    `2fa:${tempToken}`,
                    300, // 5 minutes
                    JSON.stringify({ userId: user.id, email: user.email, role: user.role })
                );

                return {
                    requiresTwoFactor: true,
                    tempToken,
                    message: 'Please enter your 2FA code',
                };
            }

            // Generate tokens
            const accessToken = generateAccessToken({
                userId: user.id,
                email: user.email,
                role: user.role,
            });

            const refreshToken = generateRefreshToken({
                userId: user.id,
                email: user.email,
                role: user.role,
            });

            // Store refresh token in database
            await prisma.refreshToken.create({
                data: {
                    userId: user.id,
                    token: refreshToken,
                    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
                },
            });

            return {
                accessToken,
                refreshToken,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role,
                },
            };
        } catch (error: any) {
            console.error('Login error:', error);
            throw error;
        }
    }

    /**
     * Setup 2FA for a user
     */
    async setup2FA(userId: string) {
        try {
            // Generate secret
            const secret = speakeasy.generateSecret({
                name: `${process.env.TWO_FACTOR_ISSUER} (${userId})`,
                length: 32,
            });

            // Store secret temporarily in Redis (10 minutes)
            await redisClient.setEx(`2fa-setup:${userId}`, 600, secret.base32);

            // Generate QR code
            const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);

            return {
                secret: secret.base32,
                qrCode: qrCodeUrl,
                message: 'Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)',
            };
        } catch (error: any) {
            console.error('Setup 2FA error:', error);
            throw error;
        }
    }

    /**
     * Verify and enable 2FA
     */
    async verify2FASetup(userId: string, token: string) {
        try {
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
                window: 2, // Allow 2 time steps before/after
            });

            if (!isValid) {
                throw new Error('Invalid 2FA code');
            }

            // Save secret to database and enable 2FA
            await prisma.user.update({
                where: { id: userId },
                data: {
                    twoFactorSecret: secret,
                    twoFactorEnabled: true,
                },
            });

            // Delete temp secret from Redis
            await redisClient.del(`2fa-setup:${userId}`);

            return {
                message: '2FA enabled successfully. You will need to use your authenticator app on future logins.',
            };
        } catch (error: any) {
            console.error('Verify 2FA setup error:', error);
            throw error;
        }
    }

    /**
     * Verify 2FA code during login
     */
    async verify2FALogin(tempToken: string, token: string) {
        try {
            // Get user data from Redis
            const userData = await redisClient.get(`2fa:${tempToken}`);

            if (!userData) {
                throw new Error('Invalid or expired session');
            }

            const { userId, email, role } = JSON.parse(userData);

            // Get user's 2FA secret
            const user = await prisma.user.findUnique({
                where: { id: userId },
                select: { twoFactorSecret: true },
            });

            if (!user || !user.twoFactorSecret) {
                throw new Error('User not found or 2FA not enabled');
            }

            // Verify token
            const isValid = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token,
                window: 2,
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
            await prisma.refreshToken.create({
                data: {
                    userId,
                    token: refreshToken,
                    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                },
            });

            return {
                accessToken,
                refreshToken,
                user: { id: userId, email, role },
            };
        } catch (error: any) {
            console.error('Verify 2FA login error:', error);
            throw error;
        }
    }

    /**
     * Disable 2FA for a user
     */
    async disable2FA(userId: string, password: string) {
        try {
            // Verify password
            const user = await prisma.user.findUnique({
                where: { id: userId },
            });

            if (!user || !user.passwordHash) {
                throw new Error('User not found');
            }

            const isValidPassword = await comparePassword(password, user.passwordHash);
            if (!isValidPassword) {
                throw new Error('Invalid password');
            }

            // Disable 2FA
            await prisma.user.update({
                where: { id: userId },
                data: {
                    twoFactorSecret: null,
                    twoFactorEnabled: false,
                },
            });

            return {
                message: '2FA disabled successfully',
            };
        } catch (error: any) {
            console.error('Disable 2FA error:', error);
            throw error;
        }
    }

    /**
     * Verify email address
     */
    async verifyEmail(token: string) {
        try {
            // Find verification token
            const verificationToken = await prisma.emailVerificationToken.findUnique({
                where: { token },
                include: { user: true },
            });

            if (!verificationToken) {
                throw new Error('Invalid verification token');
            }

            // Check if expired
            if (new Date() > verificationToken.expiresAt) {
                throw new Error('Verification token expired');
            }

            // Update user and delete token in transaction
            await prisma.$transaction([
                prisma.user.update({
                    where: { id: verificationToken.userId },
                    data: { isEmailVerified: true },
                }),
                prisma.emailVerificationToken.delete({
                    where: { id: verificationToken.id },
                }),
            ]);

            return {
                message: 'Email verified successfully. You can now log in.',
            };
        } catch (error: any) {
            console.error('Verify email error:', error);
            throw error;
        }
    }

    /**
     * Resend email verification
     */
    async resendVerificationEmail(email: string) {
        try {
            const user = await prisma.user.findUnique({
                where: { email: email.toLowerCase() },
            });

            if (!user) {
                throw new Error('User not found');
            }

            if (user.isEmailVerified) {
                throw new Error('Email is already verified');
            }

            // Delete old tokens
            await prisma.emailVerificationToken.deleteMany({
                where: { userId: user.id },
            });

            // Generate new token
            const verificationToken = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

            await prisma.emailVerificationToken.create({
                data: {
                    userId: user.id,
                    token: verificationToken,
                    expiresAt,
                },
            });

            // TODO: Send email
            console.log(`📧 Verification token: ${verificationToken}`);

            return {
                message: 'Verification email sent',
            };
        } catch (error: any) {
            console.error('Resend verification error:', error);
            throw error;
        }
    }

    /**
     * Google OAuth login/register
     */
    async googleAuth(profile: any) {
        try {
            const { id: googleId, emails, displayName } = profile;
            const email = emails[0].value.toLowerCase();

            // Find or create user
            let user = await prisma.user.findFirst({
                where: {
                    OR: [{ googleId }, { email }],
                },
            });

            if (!user) {
                // Create new user with patient profile
                user = await prisma.$transaction(async (tx) => {
                    const newUser = await tx.user.create({
                        data: {
                            email,
                            googleId,
                            role: Role.patient,
                            isEmailVerified: true, // Email is verified by Google
                        },
                    });

                    await tx.patientProfile.create({
                        data: {
                            userId: newUser.id,
                            fullName: displayName || 'User',
                        },
                    });

                    return newUser;
                });
            } else if (!user.googleId) {
                // Link Google account to existing user
                user = await prisma.user.update({
                    where: { id: user.id },
                    data: {
                        googleId,
                        isEmailVerified: true, // Email verified by Google
                    },
                });
            }

            // Check if account is active
            if (!user.isActive) {
                throw new Error('Account is deactivated');
            }

            // Generate tokens
            const accessToken = generateAccessToken({
                userId: user.id,
                email: user.email,
                role: user.role,
            });

            const refreshToken = generateRefreshToken({
                userId: user.id,
                email: user.email,
                role: user.role,
            });

            // Store refresh token
            await prisma.refreshToken.create({
                data: {
                    userId: user.id,
                    token: refreshToken,
                    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                },
            });

            return {
                accessToken,
                refreshToken,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role,
                },
            };
        } catch (error: any) {
            console.error('Google auth error:', error);
            throw error;
        }
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken(refreshToken: string) {
        try {
            // Find refresh token in database
            const tokenRecord = await prisma.refreshToken.findFirst({
                where: {
                    token: refreshToken,
                    expiresAt: { gt: new Date() },
                },
                include: { user: true },
            });

            if (!tokenRecord) {
                throw new Error('Invalid or expired refresh token');
            }

            // Generate new access token
            const accessToken = generateAccessToken({
                userId: tokenRecord.user.id,
                email: tokenRecord.user.email,
                role: tokenRecord.user.role,
            });

            return { accessToken };
        } catch (error: any) {
            console.error('Refresh token error:', error);
            throw error;
        }
    }

    /**
     * Logout user
     */
    async logout(refreshToken: string) {
        try {
            // Delete refresh token from database
            await prisma.refreshToken.deleteMany({
                where: { token: refreshToken },
            });

            return { message: 'Logged out successfully' };
        } catch (error: any) {
            console.error('Logout error:', error);
            throw error;
        }
    }

    /**
     * Logout from all devices
     */
    async logoutAllDevices(userId: string) {
        try {
            // Delete all refresh tokens for user
            await prisma.refreshToken.deleteMany({
                where: { userId },
            });

            return { message: 'Logged out from all devices' };
        } catch (error: any) {
            console.error('Logout all error:', error);
            throw error;
        }
    }
}