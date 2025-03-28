import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config(); 

const prisma = new PrismaClient();

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com", 
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER, 
    pass: process.env.SMTP_PASS, 
  },
  logger: true, 
  debug: true,  
});

const generateOTP = () => {
  return Math.floor(10000 + Math.random() * 90000).toString();
};

const sendOTPEmail = async (email: string, otp: string) => {
  try {
    const info = await transporter.sendMail({
      from: `"AuthSystem" <${process.env.SMTP_USER}>`, 
      to: email, 
      subject: "Your OTP for Authentication", 
      text: `Your OTP for account verification is: ${otp}`, 
      html: `<p>Your OTP for account verification is: <strong>${otp}</strong></p>`, 
    });

    console.log("Message sent: %s", info.messageId);
  } catch (error) {
    console.error("Error sending email:", error);
  }
};

const validatePassword = (password: string) => {
  return password.length >= 8;
};
export const register = async (req: Request, res: Response) => {
  const { username, email, password } = req.body; // Ensure `username` is included in the request body

  try {
    // Validate required fields
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Username, email, and password are required.' });
    }

    // Validate password strength
    if (!validatePassword(password)) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP
    const otp = generateOTP();

    // Create user in database
    const user = await prisma.user.create({
      data: {
        username, // ✅ Now included
        email,
        password: hashedPassword,
        otpCode: otp,
      },
    });

    // Send OTP via email
    await sendOTPEmail(email, otp);

    return res.status(201).json({ message: 'User registered successfully. OTP sent to email.', user });
  } catch (err) {
    console.error('Error registering user:', err);

    if ((err as any)?.code === 'P2002') {
      return res.status(400).json({ message: 'Email already in use' });
    }

    return res.status(500).json({ message: 'Error registering user', error: (err as Error).message });
  }
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET || 'authsecret123',
      { expiresIn: '1h' }
    );

    return res.status(200).json({ message: 'Login successful', token, user });
  } catch (err) {
    return res.status(500).json({ message: 'Error logging in', error: (err as Error).message });
  }
};

export const verifyOTP = async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.otpVerified) {
      return res.status(200).json({ message: 'User is already verified.' });
    }

    if (user.otpCode !== otp) {
      return res.status(400).json({ message: 'Invalid OTP.' });
    }

    await prisma.user.update({
      where: { email },
      data: { otpVerified: true, otpCode: null },
    });

    return res.status(200).json({ message: 'OTP verified successfully. Account activated.' });
  } catch (err) {
    return res.status(500).json({ message: 'Error verifying OTP', error: (err as Error).message });
  }
};

export const getAllUsers = async (req: Request, res: Response) => {
  try {
    const users = await prisma.user.findMany();
    return res.status(200).json({ message: 'Users fetched successfully', users });
  } catch (err) {
    return res.status(500).json({ message: 'Error fetching users', error: (err as Error).message });
  }
};

export const getUserProfile = async (req: Request, res: Response) => {
  const { id } = req.query;

  try {
    const user = await prisma.user.findUnique({ where: { id: Number(id) } });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({ message: 'Profile fetched successfully', user });
  } catch (err) {
    return res.status(500).json({ message: 'Error fetching profile', error: (err as Error).message });
  }
};

export const myProfile = async (req: Request, res: Response) => {
  const { email, username } = req.body; // Use request body instead of query

  if (!email && !username) {
    return res.status(400).json({ message: "Email or Username is required" });
  }

  const where: any = {};
  if (email) {
    where.email = email;
  } else if (username) {
    where.username = username;
  }

  try {
    const user = await prisma.user.findUnique({ where });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({ message: "Profile fetched successfully", user });
  } catch (err) {
    console.error("Error fetching profile:", err); // Debugging Log
    return res.status(500).json({ message: "Error fetching profile", error: (err as Error).message });
  }
};



export const deleteUser = async (req: Request, res: Response) => {
  const { id } = req.body;

  try {
    await prisma.user.delete({ where: { id: Number(id) } });
    return res.status(200).json({ message: 'User deleted successfully' });
  } catch (err) {
    return res.status(500).json({ message: 'Error deleting user', error: (err as Error).message });
  }
};

export const editProfile = async (req: Request, res: Response) => {
  const { id, username, email } = req.body; 

  try {
    if (!id || !username || !email) {
      return res.status(400).json({ message: 'User ID, name, and email are required.' });
    }

    const existingUser = await prisma.user.findUnique({ where: { id: Number(id) } });

    if (!existingUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Check if the new email is already in use
    const emailExists = await prisma.user.findUnique({ where: { email } });
    if (emailExists && emailExists.id !== Number(id)) {
      return res.status(400).json({ message: 'Email is already in use by another user.' });
    }

    const updatedUser = await prisma.user.update({
      where: { id: Number(id) },
      data: { username, email },
    });

    return res.status(200).json({ message: 'Profile updated successfully', user: updatedUser });
  } catch (err: any) {
    console.error('Error updating profile:', err);

    if (err.code === 'P2002') {
      return res.status(400).json({ message: 'Email is already in use by another user.' });
    }

    return res.status(500).json({ message: 'Error updating profile', error: err.message });
  }
};