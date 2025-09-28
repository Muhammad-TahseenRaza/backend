import { ACCESS_TOKEN_MAX_AGE, OAUTH_EXCHANGE_EXPIRY, REFRESH_TOKEN_MAX_AGE } from "../config/constants.js";
import { sendEmail } from "../lib/send-email.js";
import { checkUserByEmail, checkUserById, clearResetPasswordToken, clearSession, clearVerifyEmailTokens, createAccessToken, createRandomToken, createRefreshToken, createResetPasswordLink, createSession, createUser, createUserWithOauth, createVerifyEmailLink, findVerificationEmailToken, getResetPasswordToken, getShortLinkByUserId, getUserWithOauthId, hashedPassword, insertUserNameToDB, insertVerifyEmailToken, linkUserWithOauth, updateUserPassword, verifyHashPassword, verifyUserEmailAndUpdate } from "../models/02.auth.model.js";
import { loginSchema, passwordSchema, registerSchema, tokenSchema, verifyResetPasswordSchema } from "../validators/02.auth.validator.js";
import path from 'path';
import fs from 'fs/promises';
import ejs from 'ejs';
import mjml2html from 'mjml';
import z from "zod";
import { getHtmlFromMjmlTemplate } from "../lib/get-html-from-mjml.js";
import { decodeIdToken, generateCodeVerifier, generateState } from 'arctic';
import { google } from "../lib/oauth/google.js";
import { github } from "../lib/oauth/github.js";

export async function getLoginPage(req, res) {

    return res.render('auth/login', { errors: req.flash('errors') });
}

export async function postLoginPage(req, res) {

    if (req.user) {
        return res.redirect('/')
    };

    let { data, error } = loginSchema.safeParse(req.body);


    if (error) {
        let message = error.issues[0].message;
        req.flash('errors', message);
        return res.redirect('/login');
    }

    let { email, password } = data;

    let userExists = await checkUserByEmail(email);

    if (!userExists) {
        req.flash('errors', 'invalid email or password');
        return res.redirect('/login');
    }

    let isPasswordValid = await verifyHashPassword(userExists.password, password);

    if (!isPasswordValid) {
        req.flash('errors', 'invalid email or password');
        return res.redirect('/login');
    }


    let session = await createSession({
        userId: userExists.id,
        ip: req.clientIp,
        userAgent: req.headers['user-agent'],
    });

    const accessToken = createAccessToken({
        id: userExists.id,
        name: userExists.name,
        email: userExists.email,
        isEmailValid: false,
        sessionId: session.id,
    });

    const refreshToken = createRefreshToken(session.id);


    res.cookie('Access_Token', accessToken, {
        httpOnly: true,
        secure: true,
        maxAge: ACCESS_TOKEN_MAX_AGE,
    });

    res.cookie('Refresh_Token', refreshToken, {
        httpOnly: true,
        secure: true,
        maxAge: REFRESH_TOKEN_MAX_AGE,
    });

    res.redirect('/');
}


export function getRegisterPage(req, res) {

    return res.render('auth/register', { errors: req.flash('errors') });

}

export async function postRegisterPage(req, res) {

    if (req.user) {
        return res.redirect('/')
    };

    let { data, error } = registerSchema.safeParse(req.body);


    if (error) {
        let message = error.issues[0].message;
        req.flash('errors', message);
        return res.redirect('/register');
    }

    let { name, email, password } = data;

    let userExists = await checkUserByEmail(email);

    if (userExists) {
        req.flash('errors', 'User already exits');
        return res.redirect('/register');
    }

    let hashPassword = await hashedPassword(password);

    let user = await createUser({ name, email, password: hashPassword });

    let session = await createSession({
        userId: user.id,
        ip: req.clientIp,
        userAgent: req.headers['user-agent'],
    });

    const accessToken = createAccessToken({
        id: user.id,
        name: name,
        email: email,
        isEmailValid: false,
        sessionId: session.id,
    });

    const refreshToken = createRefreshToken(session.id);


    res.cookie('Access_Token', accessToken, {
        httpOnly: true,
        secure: true,
        maxAge: ACCESS_TOKEN_MAX_AGE,
    });

    res.cookie('Refresh_Token', refreshToken, {
        httpOnly: true,
        secure: true,
        maxAge: REFRESH_TOKEN_MAX_AGE,
    });


    const randomToken = createRandomToken();

    await insertVerifyEmailToken({
        userId: user.id,
        token: randomToken
    });

    const verifyEmailLink = await createVerifyEmailLink({
        email: email,
        token: randomToken,
    });

    const mjmlTemplate = await fs.readFile(path.join(import.meta.dirname, "..", 'email', 'verify-email.mjml'), 'utf-8');

    const filledTemplate = ejs.render(mjmlTemplate, { code: randomToken, link: verifyEmailLink });

    const htmlOutput = mjml2html(filledTemplate).html;

    sendEmail({
        to: email,
        subject: 'Verify your email',
        html: htmlOutput,
    });


    res.redirect('/');

}


export async function getProfilePage(req, res) {

    if (!req.user) { return res.redirect('/login') };

    let user = await checkUserById(req.user.id);

    if (!user) { return res.redirect('/404') };

    let shortLink = await getShortLinkByUserId(user.id);


    return res.render('auth/profile', {
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            avatarUrl: user.avatarUrl,
            isEmailValid: user.isEmailValid,
            createdAt: user.createdAt,
            links: shortLink,
            hasPassword: !!user.password,
        }
    })

}


export async function getVerifyEmailPage(req, res) {

    if (!req.user) { return res.redirect('/login') };

    const user = await checkUserById(req.user.id);

    if (!user || user.isEmailValid) { return res.redirect('/') };

    return res.render('auth/verify-email', {
        email: user.email,
    });

}

export async function resendVerificationLink(req, res) {

    if (!req.user) { return res.redirect('/login') };

    const user = await checkUserById(req.user.id);

    if (!user || user.isEmailValid) { return res.redirect('/') };

    const randomToken = createRandomToken();

    await insertVerifyEmailToken({
        userId: user.id,
        token: randomToken
    });

    const verifyEmailLink = await createVerifyEmailLink({
        email: user.email,
        token: randomToken,
    });

    const mjmlTemplate = await fs.readFile(path.join(import.meta.dirname, "..", 'email', 'verify-email.mjml'), 'utf-8');

    const filledTemplate = ejs.render(mjmlTemplate, { code: randomToken, link: verifyEmailLink });

    const htmlOutput = mjml2html(filledTemplate).html;

    sendEmail({
        to: user.email,
        subject: 'Verify your email',
        html: htmlOutput,
    });

    return res.redirect('/verify-email');

}


export async function getVerifyEmailToken(req, res) {

    let { data, error } = tokenSchema.safeParse(req.query);

    if (error) { return res.send('Verification link invalid') };

    const token = await findVerificationEmailToken(data);

    if (!token) { return res.send('Verification link invalid or expired!') };

    await verifyUserEmailAndUpdate(token.email);

    await clearVerifyEmailTokens(token.userId);

    res.redirect('/profile');

}


export async function getEditProfilePage(req, res) {

    if (!req.user) { return res.redirect('/login') };

    const user = await checkUserById(req.user.id);

    return res.render('auth/edit-profile', {
        name: req.user.name,
        avatarUrl: user.avatarUrl,
        errors: req.flash('errors'),
    });

}


export async function postEditProfilePage(req, res) {

    let { name } = req.body
    let { data: userName, error } = z.string().trim().min(3, { message: 'minimum 3 char' }).safeParse(name);

    if (error) {
        let message = error.issues[0].message;
        req.flash('errors', message);
        return res.redirect('/edit-profile');
    }

    // await insertUserNameToDB({ userName, userId: req.user.id });

    const fileUrl = req.file ? `uploads/avatar/${req.file.filename}` : undefined;

    await insertUserNameToDB({ userName, userId: req.user.id, avatarUrl: fileUrl});

    return res.redirect('/profile');
};


export function getChangePasswordPage(req, res) {
    if (!req.user) {
        return res.redirect('/login');
    };

    return res.render('auth/change-password', {
        errors: req.flash('errors'),
    })
}


export async function postChangePasswordPage(req, res) {

    let { data, error } = passwordSchema.safeParse(req.body);

    if (error) {
        const message = error.issues.map((err) => err.message);
        req.flash('errors', message);
        return res.redirect('/change-password');
    }

    let { currentPassword, newPassword } = data;

    const user = await checkUserById(req.user.id);
    if (!user) { return res.redirect('/404') };

    const isPasswordValid = await verifyHashPassword(user.password, currentPassword);

    if (!isPasswordValid) {
        req.flash('errors', 'Current Password that you entered is invalid');
        return res.redirect('/change-password');
    };

    await updateUserPassword({ userId: user.id, newPassword });

    return res.redirect('/profile');

}


export async function getResetPasswordPage(req, res) {

    return res.render('auth/forgot-password', {
        formSubmitted: req.flash('formSubmitted')[0],
        errors: req.flash('errors'),
    })

}


export async function postResetPasswordPage(req, res) {

    let { email } = req.body;

    let { data, error } = z.string().trim().email({ message: 'Please enter a valid email' }).safeParse(email);

    if (error) {
        const message = error.issues.map((err) => err.message);
        req.flash('errors', message);
        return res.redirect('/reset-password');
    };

    console.log(data);

    const user = await checkUserByEmail(data);

    if (!user) {
        req.flash('errors', 'this email is not exits');
        return res.redirect('/reset-password');
    };

    const resetPasswordLink = await createResetPasswordLink({ userId: user.id });

    const html = await getHtmlFromMjmlTemplate('reset-password-email', {
        name: user.name,
        link: resetPasswordLink,
    });


    sendEmail({
        to: user.email,
        subject: 'Reset Your Password',
        html,
    })

    req.flash('formSubmitted', true);

    return res.redirect('/reset-password');

}


export async function getForgetPasswordPage(req, res) {
    let { token } = req.params;

    const passwordResetData = await getResetPasswordToken(token);

    if (!passwordResetData) { return res.render('auth/wrong-reset-password-token') };

    return res.render('auth/reset-password', {
        formSubmitted: req.flash('formSubmitted')[0],
        errors: req.flash('errors'),
        token,
    })

};


export async function postForgetPasswordPage(req, res) {
    let { token } = req.params;

    const passwordResetData = await getResetPasswordToken(token);

    if (!passwordResetData) { return res.render('auth/wrong-reset-password-token') };

    const { data, error } = verifyResetPasswordSchema.safeParse(req.body);

    if (error) {
        const message = error.issues.map((err) => err.message);
        req.flash('errors', message);
        res.redirect(`/reset-password/${token}`);
    };

    const { newPassword } = data;

    const user = await checkUserById(passwordResetData.userId);

    await clearResetPasswordToken(user.id);

    await updateUserPassword({ userId: user.id, newPassword });

    return res.redirect('/login');

}


export async function logoutUser(req, res) {

    await clearSession(req.user.sessionId);

    res.clearCookie('Access_Token');
    res.clearCookie('Refresh_Token');

    return res.redirect('/login');
}


export async function getGoogleLoginPage(req, res) {

    if (req.user) {
        return res.redirect('/');
    };

    const state = generateState();
    const codeVerifier = generateCodeVerifier();

    const url = google.createAuthorizationURL(state, codeVerifier, [
        'openid',
        'profile',
        'email'
    ]);

    url.searchParams.set("prompt", "select_account");

    const cookieConfig = {
        httpOnly: true,
        secure: true,
        maxAge: OAUTH_EXCHANGE_EXPIRY,
        sameSite: 'lax',
    };

    res.cookie('google_oauth_state', state, cookieConfig);
    res.cookie('google_code_verifier', codeVerifier, cookieConfig);

    return res.redirect(url.toString());

};


export async function getGoogleLoginCallback(req, res) {

    const { code, state } = req.query;

    const { google_oauth_state: storedState, google_code_verifier: codeVerifier } = req.cookies;

    if (!code || !state || !storedState || state !== storedState) {
        req.flash('errors', '1. could not login with google because of invalid attempt');
        return res.redirect('/login');
    };

    try {
        const tokens = await google.validateAuthorizationCode(code, codeVerifier);


        const claims = decodeIdToken(tokens.data.id_token);
        const { sub: googleUserId, name, email } = claims;

        let user = await getUserWithOauthId({ provider: 'google', email });

        if (user && !user.providerAccountId) {
            await linkUserWithOauth({
                userId: user.id,
                provider: 'google',
                providerAccountId: googleUserId,
            });
        }

        if (!user) {
            user = await createUserWithOauth({
                name,
                email,
                provider: 'google',
                providerAccountId: googleUserId,
            });
        }

        let session = await createSession({
            userId: user.id,
            ip: req.clientIp,
            userAgent: req.headers['user-agent'],
        });

        const accessToken = createAccessToken({
            id: user.id,
            name,
            email,
            isEmailValid: true,
            sessionId: session.id,
        });

        const refreshToken = createRefreshToken(session.id);

        res.cookie('Access_Token', accessToken, {
            httpOnly: true,
            secure: true,
            maxAge: ACCESS_TOKEN_MAX_AGE,
        });

        res.cookie('Refresh_Token', refreshToken, {
            httpOnly: true,
            secure: true,
            maxAge: REFRESH_TOKEN_MAX_AGE,
        });

        return res.redirect('/');

    } catch (error) {
        req.flash('errors', '2. could not login with google because of invalid attempt');
        return res.redirect('/login');
    };
}


export async function getGithubLoginPage(req, res){

    if (req.user) {
        return res.redirect('/');
    };

    const state = generateState();

    const url = github.createAuthorizationURL(state, ['user:email']);


    const cookieConfig = {
        httpOnly: true,
        secure: true,
        maxAge: OAUTH_EXCHANGE_EXPIRY,
        sameSite: 'lax',
    };

    res.cookie('github_oauth_state', state, cookieConfig);

    return res.redirect(url.toString());

};


export async function getGithubLoginCallback(req, res){

    const { code, state } = req.query;

    const { github_oauth_state: storedState} = req.cookies;

    if (!code || !state || !storedState || state !== storedState) {
        req.flash('errors', 'could not login with google because of invalid attempt');
        return res.redirect('/login');
    };

    try {
        const tokens = await github.validateAuthorizationCode(code);

        const githubUserResponse = await fetch('https://api.github.com/user', {
            headers: {
                Authorization: `Bearer ${tokens.accessToken()}`,
            }
        });

        if(!githubUserResponse.ok){
            req.flash('errors', 'could not login with google because of invalid attempt');
            return res.redirect('/login');
        };

        const githubUser = await githubUserResponse.json();
        const { id: githubUserId, name } = githubUser;

        const githubEmailResponse = await fetch('https://api.github.com/user/emails', {
            headers: {
                Authorization: `Bearer ${tokens.accessToken()}`,
            }
        });

        if(!githubEmailResponse.ok){
            req.flash('errors', 'could not login with google because of invalid attempt');
            return res.redirect('/login');
        };

        const emails = await githubEmailResponse.json();
        const email = emails.filter((e)=> e.primary)[0].email;

        if(!email){
            req.flash('errors', 'could not login with google because of invalid attempt');
            return res.redirect('/login');
        }

        let user = await getUserWithOauthId({ provider: 'github', email });

        if (user && !user.providerAccountId) {
            await linkUserWithOauth({
                userId: user.id,
                provider: 'github',
                providerAccountId: githubUserId,
            });
        }

        if (!user) {
            user = await createUserWithOauth({
                name,
                email,
                provider: 'github',
                providerAccountId: githubUserId,
            });
        }

        let session = await createSession({
            userId: user.id,
            ip: req.clientIp,
            userAgent: req.headers['user-agent'],
        });

        const accessToken = createAccessToken({
            id: user.id,
            name,
            email,
            isEmailValid: true,
            sessionId: session.id,
        });

        const refreshToken = createRefreshToken(session.id);

        res.cookie('Access_Token', accessToken, {
            httpOnly: true,
            secure: true,
            maxAge: ACCESS_TOKEN_MAX_AGE,
        });

        res.cookie('Refresh_Token', refreshToken, {
            httpOnly: true,
            secure: true,
            maxAge: REFRESH_TOKEN_MAX_AGE,
        });

        return res.redirect('/');

    } catch (error) {
        req.flash('errors', '2. could not login with google because of invalid attempt');
        return res.redirect('/login');
    };

}


export async function getSetPasswordPage(req, res){
    if(!req.user){ return res.redirect('/login') };

    return res.render('auth/set-password', {
        errors: req.flash('errors'),
    })
}


export async function postSetPasswordPage(req, res){
    const {data, error} = verifyResetPasswordSchema.safeParse(req.body);

    if(error){
        let message = error.issues.map((err)=> err.message);
        req.flash('errors', message);
        return res.redirect('/set-password');
    };

    const {newPassword} = data;

    const user = await checkUserById(req.user.id);

    if(user.password){
        req.flash('errors', 'You are already have password');
        return res.redirect('/set-password');
    };

    await updateUserPassword({userId: req.user.id, newPassword});

    return res.redirect('/profile');
}