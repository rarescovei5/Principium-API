// Load Env Variables First
import { config } from 'dotenv';
import { resolve } from 'path';
config({ path: resolve(__dirname, '../.env') });

// Dependencies
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
// Source Files
import corsOptions from './config/corsOptions';
import authRouter from './routes/authRouter';
import snippetRouter from './routes/snippetRouter';

const app = express();
app.use(express.json());
app.use(cors(corsOptions));
app.use(cookieParser());

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/snippets', snippetRouter);

export default app;
