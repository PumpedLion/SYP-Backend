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


const sendOTP = async (email: string, otp: string) => {
  const mailOptions = {
    from: process.env.SMTP_USER,
    to: email,
    subject: 'OTP for MedLife',
    text: `Your OTP is: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('OTP sent successfully.');
  } catch (error) {
    console.error('Error sending OTP:', error);
  }
};



const validatePassword = (password: string) => {
  return password.length >= 8;
};

export const register = async (req: Request, res: Response) => {
  const {
    name,
    email,
    password,
    contactNo,
    userType,
    bloodType,
    location,
  } = req.body;
  console.log(req.body)

  try {
    if (!['Donor', 'Gainer'].includes(userType)) {
      return res.status(400).json({ message: 'Invalid user type. Must be Donor or Gainer.' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    let user;
    let otp;

    if (userType === 'Donor') {
      user = await prisma.donor.create({
        data: {
          name,
          email,
          password: hashedPassword,
          contactNo,
          bloodType,
          location,
        },
      });

      otp = generateOTP();
      console.log(otp, "OTP")

      await prisma.donor.update({
        where: { email: user.email },
        data: { otpCode: otp },
      });

      console.log("send mail")
      await sendOTPEmail(email, otp);

      return res.status(201).json({ message: 'Donor registered successfully. OTP sent to email.', user });
    }

    if (userType === 'Gainer') {
      user = await prisma.gainer.create({
        data: {
          name,
          email,
          password: hashedPassword,
          contactNo,
          location,
        },
      });

      otp = generateOTP();

      await prisma.gainer.update({
        where: { email: user.email },
        data: { otpCode: otp }, 
      });

      await sendOTPEmail(email, otp);

      return res.status(201).json({ message: 'Gainer registered successfully. OTP sent to email.', user });
    }
  } catch (err) {
    console.error('Error registering user:', err);

     if ((err as any)?.code === 'P2002') {
      return res.status(400).json({ message: 'Email already in use' });
    }

    return res.status(500).json({
      message: 'Error registering user',
      error: (err as Error).message,
    });
  }

  return res.status(400).json({ message: 'User registration failed' });
};

export const login = async (req: Request, res: Response) => {
  const { email, password, userType } = req.body;

  try {
    let user;

    if (userType === 'Donor') {
      user = await prisma.donor.findUnique({ where: { email } });
    } else if (userType === 'Gainer') {
      user = await prisma.gainer.findUnique({ where: { email } });
    } else {
      return res.status(400).json({ message: 'Invalid user type' });
    }

    if (!user || !user.password) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(
      password, 
      user.password || ''
    );

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id, userType },
      process.env.JWT_SECRET || 'bloodbank123', 
      { expiresIn: '1h' }
    );

    return res.status(200).json({ message: 'Login successful', token, user });
  } catch (err) {
    const error = err as Error;
    return res.status(500).json({ message: 'Error logging in', error: error.message });
  }
};

export const verifyOTP = async (req: Request, res: Response) => {
  const { email, otp, userType } = req.body;

  try {
    let user;

    if (userType === 'Donor') {
      user = await prisma.donor.findUnique({ where: { email } });
    } else if (userType === 'Gainer') {
      user = await prisma.gainer.findUnique({ where: { email } });
    } else {
      return res.status(400).json({ message: 'Invalid user type. Must be Donor or Gainer.' });
    }

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.otpVerified) {
      return res.status(200).json({ message: 'User is already verified.' });
    }

    if (user.otpCode !== otp) {
      return res.status(400).json({ message: 'Invalid OTP.' });
    }

    if (userType === 'Donor') {
      await prisma.donor.update({
        where: { email },
        data: { otpVerified: true, otpCode: null }, 
      });
    } else if (userType === 'Gainer') {
      await prisma.gainer.update({
        where: { email },
        data: { otpVerified: true, otpCode: null }, 
      });
    }

    return res.status(200).json({ message: 'OTP verified successfully. Account activated.' });
  } catch (err) {
    console.error('Error verifying OTP:', err);
    return res.status(500).json({ message: 'Error verifying OTP', error: (err as Error).message });
  }
};

export const getAllUsers = async (_req: Request, res: Response) => {
  try {
    const donors = await prisma.donor.findMany();
    const gainers = await prisma.gainer.findMany();

    return res.status(200).json({ donors, gainers });
  } catch (err) {
    console.error('Error fetching users:', err);
    return res.status(500).json({ message: 'Error fetching users', error: (err as Error).message });
  }
};

export const myProfile = async (req: Request, res: Response) => {
  const { id, userType } = req.query; // Get from query params

  try {
    let user;

    if (userType === 'Donor') {
      user = await prisma.donor.findUnique({ where: { id: Number(id) } });
    } else if (userType === 'Gainer') {
      user = await prisma.gainer.findUnique({ where: { id: Number(id) } });
    } else {
      return res.status(400).json({ message: 'Invalid user type' });
    }

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({ message: 'Profile fetched successfully', user });
  } catch (err: unknown) {  // Explicitly typing err as unknown
    console.error('Error fetching profile:', err);

    // Type assertion to Error to access message
    if (err instanceof Error) {
      return res.status(500).json({ message: 'Error fetching profile', error: err.message });
    } else {
      // Fallback for unexpected error types
      return res.status(500).json({ message: 'Unexpected error occurred' });
    }
  }
};

export const deleteUser = async (req: Request, res: Response) => {
  const { id, userType } = req.body; // Get userId and userType from the request body

  try {
    let user;

    // Check user type and perform deletion based on that
    if (userType === 'Donor') {
      user = await prisma.donor.delete({ where: { id: Number(id) } });
    } else if (userType === 'Gainer') {
      user = await prisma.gainer.delete({ where: { id: Number(id) } });
    } else {
      return res.status(400).json({ message: 'Invalid user type' });
    }

    // Check if user was found and deleted
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({ message: 'User deleted successfully' });

  } catch (err: unknown) { // Handle unknown error types
    console.error('Error deleting user:', err);

    // Type assertion to Error to access message
    if (err instanceof Error) {
      return res.status(500).json({ message: 'Error deleting user', error: err.message });
    } else {
      // Fallback for unexpected error types
      return res.status(500).json({ message: 'Unexpected error occurred' });
    }
  }
};