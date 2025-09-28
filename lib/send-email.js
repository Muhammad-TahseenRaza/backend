import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendEmail({to, subject, html}) {
    const { data, error } = await resend.emails.send({
        from: 'Website <website@resend.dev>',
        to: [to],
        subject,
        html,
    });
}