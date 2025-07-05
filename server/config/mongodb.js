import mongoose from 'mongoose'

const connectMongoDB = async () => {
  try {
    if (mongoose.connection.readyState === 1) {
      console.log('Already connected to MongoDB')
      return
    }

    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: 'mern-auth',  // Specify database name here
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    console.log('Connected to MongoDB')
  } catch (error) {
    console.error('MongoDB connection error:', error)
    process.exit(1)
  }
}

export default connectMongoDB