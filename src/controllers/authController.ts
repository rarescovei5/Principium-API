import crypto from 'crypto';
import express from 'express';
import jwt from 'jsonwebtoken';
import pool from '../model/db';
import { User } from '../model/User';

const testPassword = (password: string) => {
  if (password.length < 8) {
    return 'Password must be at least 8 characters';
  } else if (password.length > 24) {
    return 'Password must be less than 24 characters';
  } else if (!/(?=.*[a-z])/.test(password)) {
    return 'Password must contain at least one lowercase letter';
  } else if (!/(?=.*[A-Z])/.test(password)) {
    return 'Password must contain at least one uppercase letter';
  } else if (!/(?=.*\d)/.test(password)) {
    return 'Password must contain at least one number';
  }
  return '';
};
const handleRegisterUser = async (
  req: express.Request,
  res: express.Response
) => {
  const q =
    'INSERT INTO `users` (`username`, `email`, `password_hash`) VALUES (?);';
  const password = req.body.password;

  const passTestRes = testPassword(password);
  if (passTestRes.length !== 0) {
    res.status(500).json({ error: passTestRes });
    return;
  }

  try {
    const values = [
      req.body.username,
      req.body.email,
      crypto.createHash('sha256').update(password).digest('hex'),
    ];
    await pool.query(q, [values]);
    res.status(200).send({ error: 'No Error' });
  } catch (error: any) {
    if (error.code === 'ER_DUP_ENTRY') {
      let message: any = error.message.split(' ');
      message = message[message.length - 1].replace(/'/g, '');

      if (message == 'users.email') {
        res.status(500).send({ error: 'Email already registered' });
        return;
      } else if (message == 'users.username') {
        res.status(500).send({ error: 'Username taken' });
        return;
      } else {
        res.status(500).send({ error });
        return;
      }
    } else {
      res.status(500).send({ error });
      return;
    }
  }
};
const handleLoginUser = async (req: express.Request, res: express.Response) => {
  const q = 'SELECT * FROM `users` WHERE `email`=? AND `password_hash`=?';
  const values = [
    req.body.email,
    crypto.createHash('sha256').update(req.body.password).digest('hex'),
  ];
  try {
    const [d] = await pool.query(q, values);
    const data = d as User[];

    if (!process.env.ACCESS_TOKEN_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
      res.status(500).send({ error: 'Server error while logging in' });
      return;
    }

    if (data.length > 0) {
      const user_id = data[0].id;

      // Create tokens
      const accessToken = jwt.sign(
        { user_id },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '5m' }
      );
      const refreshToken = jwt.sign(
        { user_id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '1d' }
      );

      // Save Access Token
      const q = 'UPDATE `users` SET `refresh_token`=? WHERE `id`=?';

      await pool.query(q, [refreshToken, user_id]);

      res.cookie('jwt', refreshToken, {
        httpOnly: true,
        sameSite: 'none',
        secure: true,
        maxAge: 24 * 60 * 60 * 1000,
      });
      res.status(200).send({ accessToken, error: 'No Error' });
      return;
    } else {
      res.status(401).send({ error: 'Invalid credentials' });
      return;
    }
  } catch (err) {
    res.status(500).send({ error: err });
    return;
  }
};
const handleLogoutUser = async (
  req: express.Request,
  res: express.Response
) => {
  const q = 'UPDATE `users` SET `refresh_token`=NULL WHERE `refresh_token`=?';
  const cookies = req.cookies;

  if (!cookies?.jwt) {
    res.status(204).send({ error: 'No content' });
    return;
  }

  const refreshToken = cookies.jwt;

  try {
    await pool.query(q, [refreshToken]);
    res.clearCookie('jwt', {
      httpOnly: true,
      sameSite: 'none',
      secure: true,
    });
    res.status(200).send({ error: 'No Error' });
  } catch (err) {
    res.status(500).send({ error: err });
    return;
  }
};
const handleRefreshToken = async (
  req: express.Request,
  res: express.Response
) => {
  const cookies = req.cookies;

  if (!cookies?.jwt) {
    res.sendStatus(401);
    return;
  }

  const refreshToken = cookies.jwt;
  const q = 'SELECT * FROM `users` WHERE `refresh_token`=?';

  try {
    const [data] = await pool.query(q, [refreshToken]);
    if (!data || (data as any).length === 0) {
      res.status(404).send({ error: 'User not found' });
      return;
    }

    const user_id = (data as any)[0].id;

    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET!,
      (err: any, decoded: any) => {
        if (err || user_id !== (decoded as any).user_id) {
          res.sendStatus(403);
          return;
        }

        const accessToken = jwt.sign(
          { user_id },
          process.env.ACCESS_TOKEN_SECRET!,
          { expiresIn: '5m' }
        );

        res.status(200).send({ accessToken, error: 'No Error' });
      }
    );
  } catch (err) {
    res.sendStatus(403);
    return;
  }
};

export {
  handleRegisterUser,
  handleRefreshToken,
  handleLoginUser,
  handleLogoutUser,
};
