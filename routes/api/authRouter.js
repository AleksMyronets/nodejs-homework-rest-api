import express from "express";

import authController from "../../controller/authController.js";

import authenticate from "../../middlewars/authenticate.js";

import upload from "../../middlewars/upload.js";

const authRouter = express.Router();

authRouter.post('/register', authController.signup);

authRouter.post('/login', authController.signin);

authRouter.get('/current', authenticate, authController.getCurrent);

authRouter.post('/logout', authenticate, authController.logout);

authRouter.patch('/avatars', authenticate, upload.single("avatarURL"), authController.updateAvatar);

export default authRouter;
