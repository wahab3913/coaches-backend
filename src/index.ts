import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import connectDB from './config/database.js';
import authRoutes from './routes/auth.routes.js';
import playbookRoutes from './routes/playbook.routes.js';
import coachRoutes from './routes/coach.routes.js';
import adminRoutes from './routes/admin.routes.js';
import paymentRoutes from './routes/payment.routes.js';
import webhookRoutes from './routes/webhook.routes.js';
import callSessionRoutes from './routes/callSession.routes.js';
import { apiLimiter } from './middleware/rateLimiter.middleware.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Webhook route BEFORE express.json() middleware
app.use('/api/webhook', webhookRoutes);

// Middleware
const allowedOrigins = [
  'https://coach-fro.vercel.app',
  process.env.FRONTEND_URL,
  'http://localhost:3000'
].filter(Boolean) as string[];

app.use(cors({ 
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['Set-Cookie']
}));
app.use(express.json());
app.use(cookieParser());

// Rate limiting - Apply to all API routes
app.use('/api/', apiLimiter);

// Database connection
connectDB();

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/playbooks', playbookRoutes);
app.use('/api/coach', coachRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/payment', paymentRoutes);
app.use('/api/call-sessions', callSessionRoutes);

app.get('/', (req, res) => {
  res.json({ message: 'Coaches Backend API' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});