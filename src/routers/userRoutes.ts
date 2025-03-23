import express from 'express';
import { register, login, verifyOTP, getAllUsers, myProfile, deleteUser } from '../controller/userController';
import catchAsync from '../utils/catchAsync';
const router = express.Router();

router.post('/register', catchAsync(register));
router.post('/login', catchAsync(login));
router.post('/verify-otp', catchAsync(verifyOTP));
router.get('/allUsers', catchAsync(getAllUsers));
router.get('/myProfile', catchAsync(myProfile));
router.post('/deleteUser', catchAsync(deleteUser));

export default router;