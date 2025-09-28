import z from 'zod';

export const loginSchema = z.object({
    email: z.string().trim().email({ message: 'Please enter a valid email' }).max(100, { message: 'Email no longer than 100 characters' }),
    password: z.string().min(6, { message: 'password atleast 6 character long' }).max(100, {message: 'password is no longer than 100 character' }),
})

export const registerSchema = loginSchema.extend({
    name: z.string().trim().min(3, { message: 'name atleast 3 character long' }).max(100, { message: 'name no longer than 100 characters' }),
});

export const tokenSchema = z.object({
    email: z.string().trim().email({message: 'Please enter a valid email'}),
    token: z.string().trim().length(8),
});

export const passwordSchema = z.object({
    currentPassword: z.string().trim().min(1, {message: 'currentPassword at least 1 char long'}),
    newPassword: z.string().trim().min(6, {message: 'at least 6 char long'}).max(100, {message: 'no more than 100 char long'}),
    confirmPassword: z.string().trim().min(6, {message: 'at least 6 char long'}).max(100, {message: 'no more than 100 char long'}),
}).refine((data)=> data.newPassword === data.confirmPassword, {
    message: 'Password do not match',
    path: ['confirmPassword'],
});

export const verifyResetPasswordSchema = z.object({
    newPassword: z.string().trim().min(6, {message: 'at least 6 char long'}).max(100, {message: 'no more than 100 char long'}),
    confirmPassword: z.string().trim().min(6, {message: 'at least 6 char long'}).max(100, {message: 'no more than 100 char long'}),
}).refine((data)=> data.newPassword === data.confirmPassword, {
    message: 'Password do not match',
    path: ['confirmPassword'],
});