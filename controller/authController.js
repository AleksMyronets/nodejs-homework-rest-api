import User from '../models/user.js';

import HttpError from '../helpers/HttpError.js';

import userShemas from '../helpers/user-shemas.js';

import bcryptjs from "bcryptjs";

import jwt from "jsonwebtoken";

import "dotenv/config";

import fs from "fs/promises";

import path from "path";

import gravatar from "gravatar";

import Jimp from "jimp";


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

  const newUser = await User.create({ ...req.body, password: hashPassword, avatarURL });

  res.status(201).json({
    user: {
      avatarURL: newUser.avatarURL,
      email: newUser.email,
      subscription: newUser.subscription,
    },
  });
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

// const updateAvatar = async (req, res) => {
//   const { file } = req;
//     if (!file) {
//         res.status(400).json({message: "Missing files"});
//         return
//     }
//   const { path: oldPath, filename } = req.file;
//   const avatarPath = path.resolve("public", "avatars");
//   const newPath = path.join(avatarPath, filename);
//   const avatarURL = path.join("public", "avatars", filename);
//   const tmpPath = path.join("tmp", filename)
//   await fs.rename(oldPath, newPath);
//   image.resize(250, 250);
//   image.write(tmpPath);
//   const image = await Jimp.read(tmpPath);
//   const { _id } = req.user;
//   await User.findByIdAndUpdate(_id, { avatarURL: avatarURL }, { new: true });
//   res.json(avatarURL);
// }

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
    getCurrent,
    logout,
    updateAvatar
};
