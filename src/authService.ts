import { Request, Response } from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';

// User model
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Reusable Google OAuth2Client instance
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

class AuthService {
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        res.status(400).json({ error: 'Email and password are required' });
        return;
      }

      const user = await User.findOne({ email });
      if (!user) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const token = jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        token,
        user: {
          id: user._id,
          email: user.email,
          name: user.name
        }
      });
    } catch (error: any) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async register(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, name } = req.body;

      if (!email || !password || !name) {
        res.status(400).json({ error: 'Email, password, and name are required' });
        return;
      }

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        res.status(409).json({ error: 'An account with this email already exists. Please use a different email or try logging in.' });
        return;
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({
        email,
        password: hashedPassword,
        name
      });

      await user.save();

      const token = jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        success: true,
        token,
        user: {
          id: user._id,
          email: user.email,
          name: user.name
        }
      });
    } catch (error: any) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  async verify(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'No token provided' });
        return;
      }

      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, JWT_SECRET) as any;

      const user = await User.findById(decoded.userId);
      if (!user) {
        res.status(401).json({ error: 'Invalid token' });
        return;
      }

      res.json({
        success: true,
        user: {
          id: user._id,
          email: user.email,
          name: user.name
        }
      });
    } catch (error: any) {
      res.status(401).json({ error: 'Invalid token' });
    }
  }

  async refresh(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'No token provided' });
        return;
      }

      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, JWT_SECRET) as any;

      const newToken = jwt.sign(
        { userId: decoded.userId, email: decoded.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        token: newToken
      });
    } catch (error: any) {
      res.status(401).json({ error: 'Invalid token' });
    }
  }

  async logout(req: Request, res: Response): Promise<void> {
    // JWT is stateless, so logout is just client-side token removal
    res.json({ success: true, message: 'Logged out successfully' });
  }

  async forgotPassword(req: Request, res: Response): Promise<void> {
    // TODO: Implement password reset
    res.status(501).json({ error: 'Not implemented' });
  }

  async resetPassword(req: Request, res: Response): Promise<void> {
    // TODO: Implement password reset
    res.status(501).json({ error: 'Not implemented' });
  }

  async googleLogin(req: Request, res: Response): Promise<void> {
    try {
      const { idToken } = req.body;

      if (!idToken) {
        res.status(400).json({ error: 'idToken is required' });
        return;
      }

      // Verify Google idToken
      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID
      });

      const payload = ticket.getPayload();
      if (!payload) {
        res.status(401).json({ error: 'Invalid Google token' });
        return;
      }

      // Extract user info from payload
      const { sub, email, name } = payload;
      
      if (!email) {
        res.status(401).json({ error: 'Invalid Google token - email not found' });
        return;
      }

      // Use name from payload or fallback to email prefix
      const userName = name || email.split('@')[0];

      // Look up user by email
      let user = await User.findOne({ email });

      // Create user if doesn't exist
      if (!user) {
        // Generate a random strong password since password is required in schema
        const randomPassword = crypto.randomBytes(32).toString('hex');
        const hashedPassword = await bcrypt.hash(randomPassword, 10);
        
        user = new User({
          email,
          password: hashedPassword,
          name: userName
        });

        await user.save();
      }

      // Issue JWT token (same as login/register)
      const token = jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      // Return response in same format as login/register
      res.json({
        success: true,
        token,
        user: {
          id: user._id,
          email: user.email,
          name: user.name
        }
      });
    } catch (error: any) {
      console.error('Google login error:', error);
      
      // If it's a Google verification error, return 401
      if (error.message && error.message.includes('Token used too early') || 
          error.message && error.message.includes('Token used too late') ||
          error.message && error.message.includes('Invalid token')) {
        res.status(401).json({ error: 'Invalid Google token' });
        return;
      }
      
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}

export default new AuthService();

