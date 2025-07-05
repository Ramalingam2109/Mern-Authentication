import express from 'express'
import {
  login,
  register,
  logout,
  sendVerifyOtp,
  verifyEMail,
} from '../controllers/authController.js'
import userAuth from '../middleware/userAuth.js'

const router = express.Router()

router.post('/register', register)
router.post('/login', login)
router.post('/logout', logout)
router.post('/send-verify-otp', userAuth, sendVerifyOtp)
router.post('/verify-account', userAuth, verifyEMail)
export { router as authRouter }
