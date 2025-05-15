import express from 'express';
import * as authController from '../controllers/authController';

const authRouter = express.Router();

authRouter
  .post('/register', authController.handleRegisterUser)
  .post('/login', authController.handleLoginUser)
  .get('/logout', authController.handleLogoutUser)
  .get('/refresh', authController.handleRefreshToken);

export default authRouter;
