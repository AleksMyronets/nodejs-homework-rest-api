import User from '../models/user.js';

import userShemas from '../helpers/user-shemas.js';

import { HttpError, sendEmail, createVerifyEmail } from '../helpers/index.js';

import bcryptjs from "bcryptjs";

import jwt from "jsonwebtoken";

import "dotenv/config";

import fs from "fs/promises";

import path from "path";

import gravatar from "gravatar";

import Jimp from "jimp";

import { nanoid } from 'nanoid';


const { JWT_SECRET } = process.env;


const signup = async (req, res, next) => {
  const { error } = userShemas.userSignupShema.validate(req.body);
  if (error) {
    return next(HttpError(400, error.message));
  }

  const { email, password } = req.body;
  const avatarURL = gravatar.url(email, { s: '200' });
  const user = await User.findOne({ email });
  if (user) {
    return next(HttpError(409, "Email in use"));
  }

  const hashPassword = await bcryptjs.hash(password, 10);

  const verificationToken = nanoid();

  const newUser = await User.create({ ...req.body, password: hashPassword, avatarURL, verificationToken });

  const verifyEmail = createVerifyEmail({email, verificationToken});

  await sendEmail(verifyEmail);

  res.status(201).json({
    user: {
      avatarURL: newUser.avatarURL,
      email: newUser.email,
      subscription: newUser.subscription,
    },
  });
};

const verify = async (req, res, next) => {
  const { verificationToken } = req.params;
  const user = await User.findOne({ verificationToken });
  if (!user) {
     return next(HttpError(404, "User not found"));
  }
  await User.findByIdAndUpdate(user._id, { verify: true, verificationToken: "" });

  res.json({
      message: "Verify successful"
  })
};

const signin = async (req, res, next) => {
  const { error } = userShemas.userSigninShema.validate(req.body);
  if (error) {
    return next(HttpError(400, error.message));
    
  }
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return next(HttpError(401, "Email or password is wrong"));
  }

  if (!user.verify) {
    return next(HttpError(401, "Email not verify"));
  }

  const passwordCompare = await bcryptjs.compare(password, user.password);
  
  if (!passwordCompare) {
    return next(HttpError(401, "Email or password is wrong"));
  }

  const payload = {
    id: user._id,
  };

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "23h" });

  await User.findByIdAndUpdate(user._id, { token });

  res.status(200).json({
    token,
    user: {
      email: user.email,
      subscription: user.subscription,
    },
  });
};

const resendVerifyEmail = async (req, res, next) => {

  const { error } = userShemas.userEmailShema.validate(req.body);
  if (error) {
    return next(HttpError(400, error.message));
  }

  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return next(HttpError(404, "Email not found"));
  }

  if (user.verify) {
    return next(HttpError(400, "Verification has already been passed"))
  }

  const verifyEmail = createVerifyEmail({email, verificationToken: user.verificationToken});

  await sendEmail(verifyEmail);

  res.json({
    message: "Verification email sent"
  })
};

const getCurrent = (req, res) => {
  const { subscription, email } = req.user;
  res.json({
    email,
    subscription
  });
};

const logout = async (req, res) => {
  const { _id } = req.user;
  await User.findByIdAndUpdate(_id, { token: "" });
  res.status(204).json({
    message: "Logout success",
  });
};

const updateAvatar = async (req, res) => { 
    const { file } = req;
    if (!file) {
        res.status(400).json({message: "Missing files"});
        return
    }
    const { path: oldPath, filename } = req.file;
    const tmpPath = path.join("tmp", filename)
    const image = await Jimp.read(tmpPath);
    const avatarPath = path.resolve("public", "avatars");
    const newPath = path.join(avatarPath, filename);
    const avatarURL = path.join("avatars", filename);
    const { _id } = req.user;
  
    image.resize(250, 250);
    image.write(tmpPath);
  
    await fs.rename(oldPath, newPath);
    await User.findByIdAndUpdate(_id, { avatarURL: avatarURL }, { new: true });

    res.json({avatarURL: avatarURL});
}

export default {
    signup,
    signin,
    verify,
    resendVerifyEmail,
    getCurrent,
    logout,
    updateAvatar
};
