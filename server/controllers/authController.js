import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import userModel from '../models/userModel.js'
import transporter from '../config/nodeMailer.js'

export const register = async (req, res) => {
  const { name, email, password } = req.body

  if (!name || !email || !password) {
    return res.json({ success: false, message: 'Missing details' })
  }
  try {
    const existingUser = await userModel.findOne({ email })
    if (existingUser) {
      return res.json({ success: false, message: 'User already exists' })
    }
    const hashedPassword = await bcrypt.hash(password, 10)

    const user = new userModel({ name, email, password: hashedPassword })
    await user.save()

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    const mailOptions = {
      from: process.env.SENDER_MAIL,
      to: email,
      subject: 'Welcome mail',
      text: `Welcome to Authenticator demo ,  Your account has been created with mail id : ${email} for ${name}`,
    }
    await transporter.sendMail(mailOptions)

    return res.json({ success: true })
  } catch (error) {
    res.json({ success: false, message: error.message })
  }
}

export const login = async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.json({ success: false, message: ' email and password are required' })
  }

  try {
    const user = await userModel.findOne({ email })

    if (!user) {
      return res.json({ success: false, message: 'Invalid email' })
    }
    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.json({ success: false, message: 'Invalid credentials' })
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    return res.json({ success: true })
  } catch (error) {
    res.json({ success: false, message: error.message })
  }
}

export const logout = async (req, res) => {
  try {
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      path: '/', // Add this to ensure same path as set cookie
    })

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    })
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Logout failed',
      error: error.message,
    })
  }
}

export const sendVerifyOtp = async (req, res) => {
  try {
    const { userId } = req.body
    const user = await userModel.findById(userId)

    if (!user) {
      return res.json({ success: false, message: 'User not found' })
    }

    if (user.isAccountVerified) {
      return res.json({ success: false, message: 'Account already verified' })
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000))
    user.verifyOTP = otp
    user.verifyOTPExpireAt = Date.now() + 24 * 60 * 60 * 1000
    await user.save()

    const mailOptions = {
      from: process.env.SENDER_MAIL,
      to: user.email, // Use user.email from the found user
      subject: 'Verification Mail',
      text: `Your OTP for email verification is ${otp}. Verify your account using this OTP.`,
    }

    await transporter.sendMail(mailOptions)

    res.json({ success: true, message: 'Verification OTP sent to your email' })
  } catch (error) {
    console.error('Error sending OTP:', error)
    return res.status(500).json({
      success: false,
      message: 'Failed to send OTP',
      error: error.message,
    })
  }
}

export const verifyEMail = async (req, res) => {
  const { userId, otp } = req.body

  // Check for userId and otp instead of user
  if (!userId || !otp) {
    return res.json({ success: false, message: 'Missing Details' })
  }

  try {
    const user = await userModel.findById(userId)

    if (!user) {
      return res.json({ success: false, message: 'User not found' })
    }

    if (user.verifyOTP === '' || user.verifyOTP !== otp) {
      return res.json({ success: false, message: 'Invalid OTP' })
    }

    if (user.verifyOTPExpireAt < Date.now()) {
      return res.json({ success: false, message: 'OTP Expired' })
    }

    user.isVerified = true
    user.verifyOTP = ''
    user.verifyOTPExpireAt = 0
    await user.save()

    return res.json({ success: true, message: 'Email verified successfully' })
  } catch (error) {
    console.error('Verification error:', error)
    return res.status(500).json({
      success: false,
      message: 'Verification failed',
      error: error.message,
    })
  }
}

export const isAuthenticated = async (req, res) => {
  try {
    res.json({ success: true })
  } catch (error) {
    res.json({ success: false, message: error.message })
  }
}

export const sendResetOTP = async (req, res) => {
  const { email } = req.body
  if (!email) {
    return res.json({ success: false, message: 'email is required ' })
  }
  try {
    const user = await userModel.findOne({ email })
    if (!email) {
      res.json({ success: false, message: 'User not found' })
    } else {
      const otp = String(Math.floor(100000 + Math.random() * 900000))
      user.resetOTP = otp
      user.resetOTPExpireAT = Date.now() + 15 * 60 * 1000
      await user.save()

      const mailOptions = {
        from: process.env.SENDER_MAIL,
        to: user.email, // Use user.email from the found user
        subject: 'Reset OTP',
        text: `Your OTP for resetting password is ${otp}. Use this to reset your password.`,
      }

      await transporter.sendMail(mailOptions)

      res.json({ success: true, message: 'Verification OTP sent to your email' })
    }
  } catch (error) {
    res.json({ success: false, message: error.message })
  }
}

export const ResetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body
  if (!email || !otp || !newPassword) {
    res.json({ success: false, message: 'Invalid Credentials' })
  }
  try {
    const user = await userModel.findOne({ email })

    if (!user) {
      res.json({ success: false, message: 'User not found ' })
    }

    if (user.resetOTP == '' || user.resetOTP != otp) {
      return res.json({
        success: false,
        message: 'InValid OTP',
      })
    }

    if (user.resetOTPExpireAT < Date.now()) {
      return res.json({ success: false, message: 'OTP Expired' })
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10)
    user.password = hashedPassword
    user.resetOTP = ''
    user.resetOTPExpireAT = 0
    await user.save()
    res.json({ success: true, message: 'Password has been reset successfully' })
  } catch (error) {
    res.json({ success: false, message: error.message })
  }
}
