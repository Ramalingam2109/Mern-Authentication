import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import cookieParser from 'cookie-parser'
import connectMongoDB from './config/mongodb.js'
import { authRouter } from './routes/authRoutes.js'

const app = express()
const port = process.env.PORT || 3000
connectMongoDB()

app.use(express.json())
app.use(cookieParser())
app.use(cors({ credentials: true }))
app.listen(port, () => {
  console.log(`Server Started on ${port}`)
})

app.get('/', (req, res) => {
  res.send('API Working ')
})
app.use('/api/auth', authRouter)
