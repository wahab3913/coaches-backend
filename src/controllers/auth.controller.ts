import type { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import User from '../models/User.model.js';
import Company from '../models/Company.model.js';
import LoginSession from '../models/LoginSession.model.js';
import type { AuthRequest } from '../middleware/auth.middleware.js';
import { sendPasswordResetEmail, sendEmailVerification } from '../utils/email.util.js';
import { parseUserAgent, getClientIp } from '../utils/deviceParser.util.js';

export const signup = async (req: Request, res: Response) => {
  try {
    const { fullName, email, password, role, companyName, ownerName, ownerEmail } = req.body;

    // Map frontend roles to backend roles
    const roleMapping: Record<string, string> = {
      'individual': 'sales',
      'company': 'coach'
    };
    const mappedRole = roleMapping[role] || role;

    // Use consistent email field for all roles
    const userEmail = mappedRole === 'sales' ? email : ownerEmail;
    const userName = mappedRole === 'sales' ? fullName : ownerName;

    const existingUser = await User.findOne({ email: userEmail });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate email verification token (random 32-byte hex string)
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Hash the token before saving to database
    const hashedToken = crypto.createHash('sha256').update(verificationToken).digest('hex');

    const user = new User({
      name: userName,
      email: userEmail,
      password: hashedPassword,
      role: mappedRole,
      companyName: mappedRole === 'coach' ? companyName : undefined,
      isEmailVerified: false,
      emailVerificationToken: hashedToken,
      emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      subscription: {
        plan: 'Free',
        status: 'Trial',
        billingCycle: 'Monthly',
        startDate: new Date(),
        nextBillingDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days trial
      }
    });

    await user.save();

    // Create Company entry if user is a coach
    let company = null;
    if (mappedRole === 'coach' && companyName) {
      try {
        // Check if company with same name or owner email already exists
        const existingCompany = await Company.findOne({
          $or: [
            { name: companyName },
            { ownerEmail: userEmail }
          ]
        });
        
        if (existingCompany) {
          await User.deleteOne({ _id: user._id });
          return res.status(400).json({ message: 'Company with this name or owner email already exists' });
        }
        
        company = new Company({
          name: companyName,
          ownerName: userName,
          ownerEmail: userEmail,
          ownerId: user._id,
          status: 'pending'
        });
        await company.save();
        
        // Update user with companyId
        user.companyId = company._id as any;
        await user.save();
      } catch (companyError) {
        // If company creation fails, delete the user
        await User.deleteOne({ _id: user._id });
        return res.status(500).json({ message: 'Failed to create company. Please try again.' });
      }
    }

    // Send verification email
    try {
      await sendEmailVerification(userEmail, userName, verificationToken);
    } catch (emailError) {
      // If email fails, delete the user and company
      await User.deleteOne({ _id: user._id });
      if (company) {
        await Company.deleteOne({ _id: company._id });
      }
      return res.status(500).json({ message: 'Failed to send verification email. Please try again.' });
    }

    res.status(201).json({
      message: 'Account created successfully! Please check your email to verify your account.',
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: 'Please verify your email before logging in. Check your inbox for the verification link.',
        emailVerified: false
      });
    }

    // Update last login timestamp and increment login count
    user.lastLoginAt = new Date();
    user.loginCount = (user.loginCount || 0) + 1;
    await user.save();

    // Create login session
    const userAgent = req.headers['user-agent'] || '';
    const ipAddress = getClientIp(req);
    const { browser, os, device } = parseUserAgent(userAgent);

    await LoginSession.create({
      userId: user._id,
      userAgent,
      ipAddress,
      browser,
      os,
      device,
      isActive: true
    });

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '1d' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 1 * 24 * 60 * 60 * 1000,
      path: '/'
    });

    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

export const logout = async (req: AuthRequest, res: Response) => {
  try {
    // Mark active sessions as inactive
    if (req.user?.userId) {
      await LoginSession.updateMany(
        { userId: req.user.userId, isActive: true },
        { isActive: false, logoutTime: new Date() }
      );
    }

    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      path: '/'
    });

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

export const verifyAuth = async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.user?.userId).select('-password');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email, 
        role: user.role, 
        companyName: user.companyName,
        subscription: user.subscription
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const user = await User.findOne({ email });

    // Always return success message (security best practice - don't reveal if email exists)
    if (!user) {
      return res.json({
        message: 'If an account exists with this email, you will receive a password reset link shortly.'
      });
    }

    // Generate reset token (random 32-byte hex string)
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Hash the token before saving to database
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    // Save hashed token and expiry to user
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now
    await user.save();

    // Send email with unhashed token
    try {
      await sendPasswordResetEmail(user.email, user.name, resetToken);
    } catch (emailError) {
      // If email fails, clear the reset token
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();
      return res.status(500).json({ message: 'Failed to send reset email. Please try again later.' });
    }

    res.json({
      message: 'If an account exists with this email, you will receive a password reset link shortly.'
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ message: 'Token and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }

    // Hash the token from URL to compare with database
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with valid reset token that hasn't expired
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update password and clear reset token fields
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    res.json({ message: 'Password reset successful. You can now log in with your new password.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: 'Verification token is required' });
    }

    // Hash the token from URL to compare with database
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with valid verification token that hasn't expired
    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    // Mark email as verified and clear verification token fields
    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationExpires = null;
    await user.save();

    // If user is a coach, update company status to active
    if (user.role === 'coach' && user.companyId) {
      await Company.findByIdAndUpdate(user.companyId, { status: 'active' });
    }

    res.json({ message: 'Email verified successfully! You can now log in.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

export const resendVerification = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const user = await User.findOne({ email });

    if (!user) {
      // Don't reveal if email exists (security best practice)
      return res.json({ message: 'If an account exists with this email, a verification link will be sent.' });
    }

    if (user.isEmailVerified) {
      return res.json({ message: 'Email is already verified.' });
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(verificationToken).digest('hex');

    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await user.save();

    try {
      await sendEmailVerification(user.email, user.name, verificationToken);
    } catch (emailError) {
      return res.status(500).json({ message: 'Failed to send verification email.' });
    }

    res.json({ message: 'If an account exists with this email, a verification link will be sent.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

export const setupRepAccount = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ message: 'Token and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }

    // Hash the token to compare with database
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with valid invitation token
    const user = await User.findOne({
      invitationToken: hashedToken,
      invitationExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired invitation token' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user with password and mark as verified
    user.password = hashedPassword;
    user.isEmailVerified = true;
    user.invitationToken = null;
    user.invitationExpires = null;
    await user.save();

    res.json({ message: 'Account setup successful! You can now log in.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};


export const setupCoachAccount = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ message: 'Token and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      invitationToken: hashedToken,
      invitationExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired invitation token' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user.password = hashedPassword;
    user.isEmailVerified = true;
    user.invitationToken = null;
    user.invitationExpires = null;
    await user.save();

    res.json({ message: 'Account setup successful! You can now log in.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};