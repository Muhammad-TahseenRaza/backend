import { Router } from "express";
import { getChangePasswordPage, getEditProfilePage, getForgetPasswordPage,  getGithubLoginCallback,  getGithubLoginPage,  getGoogleLoginCallback,  getGoogleLoginPage, getLoginPage, getProfilePage, getRegisterPage, getResetPasswordPage, getSetPasswordPage, getVerifyEmailPage, getVerifyEmailToken, logoutUser, postChangePasswordPage, postEditProfilePage, postForgetPasswordPage, postLoginPage, postRegisterPage, postResetPasswordPage, postSetPasswordPage, resendVerificationLink } from "../controllers/02.auth.controller.js";
import multer from 'multer';
import path from 'path';

let router = Router();


router.route('/login').get(getLoginPage).post(postLoginPage);

router.route('/register').get(getRegisterPage).post(postRegisterPage);

router.route('/profile').get(getProfilePage);

router.route('/verify-email').get(getVerifyEmailPage);

router.route('/resend-verification-link').post(resendVerificationLink);

router.route('/verify-email-token').get(getVerifyEmailToken);

const avatarStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/avatar');
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `${Date.now()}_${Math.random()}${ext}`);
    },
});

const avatarFileFilter = (req, file, cb) => {
    if(file.mimetype.startsWith('image/')){
        cb(null, true);
    }else{
        cb(new Error('Only image files are allowed!'), false);
    };
};

const avatarUpload = multer({
    storage: avatarStorage,
    fileFilter: avatarFileFilter,
    limits: {fileSize: 5 * 1024 * 1024},
})

router.route('/edit-profile').get(getEditProfilePage).post(avatarUpload.single('avatar'), postEditProfilePage);

router.route('/change-password').get(getChangePasswordPage).post(postChangePasswordPage);

router.route('/reset-password').get(getResetPasswordPage).post(postResetPasswordPage);

router.route('/reset-password/:token').get(getForgetPasswordPage).post(postForgetPasswordPage);

router.route('/google').get(getGoogleLoginPage);

router.route('/google/callback').get(getGoogleLoginCallback);

router.route('/github').get(getGithubLoginPage);

router.route('/github/callback').get(getGithubLoginCallback);

router.route('/set-password').get(getSetPasswordPage).post(postSetPasswordPage);

router.route('/logout').get(logoutUser);

export const authRoutes = router;