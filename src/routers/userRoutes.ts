import express from 'express';
import { register, login, verifyOTP, getAllUsers, myProfile, deleteUser, editProfile } from '../controller/userController';
import catchAsync from '../utils/catchAsync';
const router = express.Router();

router.post('/register', catchAsync(register));
router.post('/login', catchAsync(login));
router.post('/verify-otp', catchAsync(verifyOTP));
router.get('/allUsers', catchAsync(getAllUsers));
router.get('/myProfile', catchAsync(myProfile));
router.delete('/deleteUser', catchAsync(deleteUser));
router.patch('/editProfile', catchAsync(editProfile));

export default router;