import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcryptjs from 'bcryptjs';

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  try {
    // Find user by username using Sequelize's `where` clause
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Verify password
    const validPassword = await bcryptjs.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Create JWT token
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET as string, {
      expiresIn: '1h',
    });

    // Return the token
    return res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
