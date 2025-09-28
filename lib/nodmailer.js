import nodemailer from 'nodemailer';

const textAccount = await nodemailer.createTestAccount();

const transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false,
    auth: {
        user: "celine45@ethereal.email",
        pass: "tzFvsuB9GxnRncv7hS",
    },
});

export async function sendEmail({ to, subject, html }) {
    const info = await transporter.sendMail({
        from: `'URL Shortener' < ${textAccount.user} >`,
        to,
        subject,
        html,
    });

    const testEmailURL = nodemailer.getTestMessageUrl(info);
    console.log('verifyEmail', testEmailURL);

};