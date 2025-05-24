import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import pool from '../model/db';

const testPassword = (password: string): string => {
  if (password.length < 8) {
    return 'Password must be at least 8 characters';
  } else if (password.length > 50) {
    return 'Password must be less than 50 characters';
  } else if (!/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter';
  } else if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter';
  } else if (!/\d/.test(password)) {
    return 'Password must contain at least one number';
  }
  return '';
};

const handleRegisterUser = async (req: express.Request, res: express.Response) => {
  const { firstName, lastName, email, password } = req.body;
  if (!(firstName && lastName && email && password)) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Test Password
  const pwdErr = testPassword(password);
  if (pwdErr) {
    return res.status(400).json({ error: pwdErr });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    const sql = `
      INSERT INTO \`users\`
        (\`first_name\`, \`last_name\`, \`email\`, \`password_hash\`)
      VALUES (?,?,?,?)
    `;
    await pool.query(sql, [firstName, lastName, email, passwordHash]);

    return res.status(201).json({ error: null });
  } catch (err: any) {
    // Handle duplicates
    if (err.code === 'ER_DUP_ENTRY') {
      if (err.sqlMessage.includes('users.email')) {
        return res.status(409).json({ error: 'Email already registered' });
      }
      // I deleted it from db but will add back
      if (err.sqlMessage.includes('users.username')) {
        return res.status(409).json({ error: 'Username taken' });
      }
    }

    // Idk any other errors
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'Server error during registration' });
  }
};

const handleLoginUser = async (req: express.Request, res: express.Response) => {
  const { email, password } = req.body;
  if (!(email && password)) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const sqlSelect = `
      SELECT \`id\`, \`password_hash\`
      FROM \`users\`
      WHERE \`email\` = ?
    `;
    const [rows] = await pool.query(sqlSelect, [email]);
    const users = rows as { id: number; password_hash: string }[];

    if (users.length === 0) {
      // no such email
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { id: userId, password_hash: storedHash } = users[0];

    const match = await bcrypt.compare(password, storedHash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = process.env;

    // Sign tokens
    const accessToken = jwt.sign({ userId }, ACCESS_TOKEN_SECRET!, {
      expiresIn: '5m',
    });
    const refreshToken = jwt.sign({ userId }, REFRESH_TOKEN_SECRET!, {
      expiresIn: '1d',
    });

    //  Persist refresh token
    const sqlUpdate = 'UPDATE `users` SET `refresh_token` = ? WHERE `id` = ?';
    await pool.query(sqlUpdate, [refreshToken, userId]);

    // Send cookie + JSON
    res
      .cookie('jwt', refreshToken, {
        httpOnly: true,
        sameSite: 'none',
        secure: true,
        maxAge: 24 * 60 * 60 * 1000,
      })
      .status(200)
      .json({ accessToken, error: null });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error while logging in' });
  }
};

const handleLogoutUser = async (req: express.Request, res: express.Response) => {
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
const handleRefreshToken = async (req: express.Request, res: express.Response) => {
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

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!, (err: any, decoded: any) => {
      if (err || user_id !== (decoded as any).user_id) {
        res.sendStatus(403);
        return;
      }

      const accessToken = jwt.sign({ user_id }, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: '5m' });

      res.status(200).send({ accessToken, error: 'No Error' });
    });
  } catch (err) {
    res.sendStatus(403);
    return;
  }
};

export { handleRegisterUser, handleRefreshToken, handleLoginUser, handleLogoutUser };
