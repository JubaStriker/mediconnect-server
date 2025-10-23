// src/controllers/auth.controller.ts
import { Request, Response } from 'express';
import { AuthService } from '../services/auth.services';
import prisma from '../lib/prisma';

const authService = new AuthService();

export class AuthController {
    async register(req: Request, res: Response) {
        try {
            const result = await authService.register(req.body);
            res.status(201).json(result);
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }

    async login(req: Request, res: Response) {
        try {
            const { email, password } = req.body;
            const result = await authService.login(email, password);

            // Set refresh token as httpOnly cookie
            if (result.refreshToken) {
                res.cookie('refreshToken', result.refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                });
            }

            res.json(result);
        } catch (error: any) {
            res.status(401).json({ error: error.message });
        }
    }

    async setup2FA(req: Request, res: Response) {
        try {
            const userId = req.user!.userId;
            const result = await authService.setup2FA(userId);
            res.json(result);
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }

    async verify2FASetup(req: Request, res: Response) {
        try {
            const userId = req.user!.userId;
            const { token } = req.body;
            const result = await authService.verify2FASetup(userId, token);
            res.json(result);
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }

    async disable2FA(req: Request, res: Response) {
        try {
            const userId = req.user!.userId;
            const { password } = req.body;
            const result = await authService.disable2FA(userId, password);
            res.json(result);
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }

    async verify2FALogin(req: Request, res: Response) {
        try {
            const { tempToken, token } = req.body;
            const result = await authService.verify2FALogin(tempToken, token);

            res.cookie('refreshToken', result.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000,
            });

            res.json(result);
        } catch (error: any) {
            res.status(401).json({ error: error.message });
        }
    }

    async verifyEmail(req: Request, res: Response) {
        try {
            const { token } = req.params;
            const result = await authService.verifyEmail(token);
            res.json(result);
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }

    async resendVerificationEmail(req: Request, res: Response) {
        try {
            const { email } = req.body;
            const result = await authService.resendVerificationEmail(email);
            res.json(result);
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }

    async refreshToken(req: Request, res: Response) {
        try {
            const refreshToken = req.cookies.refreshToken;

            if (!refreshToken) {
                return res.status(401).json({ error: 'Refresh token not found' });
            }

            const result = await authService.refreshAccessToken(refreshToken);
            res.json(result);
        } catch (error: any) {
            res.status(401).json({ error: error.message });
        }
    }

    async logout(req: Request, res: Response) {
        try {
            const refreshToken = req.cookies.refreshToken;

            if (refreshToken) {
                await authService.logout(refreshToken);
            }

            res.clearCookie('refreshToken');
            res.json({ message: 'Logged out successfully' });
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }

    async logoutAllDevices(req: Request, res: Response) {
        try {
            const userId = req.user!.userId;
            const result = await authService.logoutAllDevices(userId);

            res.clearCookie('refreshToken');
            res.json(result);
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }

    async getProfile(req: Request, res: Response) {
        try {
            const userId = req.user!.userId;
            const role = req.user!.role;

            // Get user with profile
            const user = await prisma.user.findUnique({
                where: { id: userId },
                select: {
                    id: true,
                    email: true,
                    role: true,
                    isEmailVerified: true,
                    twoFactorEnabled: true,
                    createdAt: true,
                    doctorProfile: role === 'doctor',
                    patientProfile: role === 'patient',
                },
            });

            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            res.json(user);
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    }
}