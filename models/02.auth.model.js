import {db} from '../config/drizzle.js';
import {eq, sql, lt, gte, and} from 'drizzle-orm'
import { sessionsTable, shortLinks, usersTable, emailVerifications, passwordResetTokensTable, oauthAccountTable } from '../drizzle/schema.js';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY } from '../config/constants.js';
import crypto from 'crypto';


export async function checkUserByEmail(email){

    let [userEmail] = await db.select().from(usersTable).where(eq(usersTable.email, email));

    return userEmail;

}


export async function createUser({name, email, password}){
    let [user] = await db.insert(usersTable).values({name, email, password}).$returningId();
    return user;
}


export async function hashedPassword(password){
    return await argon2.hash(password);
}


export async function verifyHashPassword(hashPassword, password){
    return await argon2.verify(hashPassword, password);
}


export async function createSession({userId, ip, userAgent}){
    let [session] = await db.insert(sessionsTable).values({userId, ip, userAgent}).$returningId();
    return session;
};

export function createAccessToken({id, name, email, sessionId}){
    return jwt.sign({id, name, email, sessionId}, process.env.JWT_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRY,
    });
};


export function createRefreshToken(sessionId){
    return jwt.sign({sessionId}, process.env.JWT_SECRET, {
        expiresIn: REFRESH_TOKEN_EXPIRY,
    });
};


export function verifyJWTToken(token){

    return jwt.verify(token, process.env.JWT_SECRET);

}


export async function checkSessionById(sessionId){
    let [session] =  await db.select().from(sessionsTable).where(eq(sessionsTable.id, sessionId));
    return session;
}

export async function checkUserById(userId){
    let [user] = await db.select().from(usersTable).where(eq(usersTable.id, userId));
    return user;
}

export async function clearSession(sessionId){
    await db.delete(sessionsTable).where(eq(sessionsTable.id, sessionId));
}

export async function getShortLinkByUserId(userId){
    return await db.select().from(shortLinks).where(eq(shortLinks.userId, userId));
}

export function createRandomToken(digit = 8){
    let min = 10 ** (digit - 1);
    let max = 10 ** digit;

    return crypto.randomInt(min, max).toString();
}

export async function insertVerifyEmailToken({userId, token}){

    return db.transaction(async (tx)=>{

        await tx.delete(emailVerifications).where(lt(emailVerifications.expiresAt, sql`CURRENT_TIMESTAMP`));

        await tx.delete(emailVerifications).where(eq(emailVerifications.userId, userId));

        await tx.insert(emailVerifications).values({userId, token});
    })
}

export async function createVerifyEmailLink({email, token}){
    const url = new URL(`${process.env.FRONTEND_URL}/verify-email-token`);

    url.searchParams.append('token', token);
    url.searchParams.append('email', email);

    return url.toString();
}

export async function findVerificationEmailToken({token, email}){
    
    let [tokenUser] = await db.select().from(emailVerifications).where(and(eq(emailVerifications.token, token), gte(emailVerifications.expiresAt, sql`CURRENT_TIMESTAMP`)));

    if(!tokenUser){
        return null;
    }

    let [user] = await db.select().from(usersTable).where(eq(usersTable.id, tokenUser.userId));

    if(!user){
        return null;
    };

    return {
        userId: user.userId,
        email: user.email,
        token: tokenUser.token,
        expiresAt: tokenUser.expiresAt,
    }

}

export async function verifyUserEmailAndUpdate(email){
    return await db.update(usersTable).set({isEmailValid: true}).where(eq(usersTable.email, email));
}

export async function clearVerifyEmailTokens(userId){
    return await db.delete(emailVerifications).where(eq(emailVerifications.userId, userId));
}

export async function insertUserNameToDB({userName, userId, avatarUrl}){
    await db.update(usersTable).set({name: userName, avatarUrl}).where(eq(usersTable.id, userId));
}


export async function updateUserPassword({userId, newPassword}){
    const newHashPassword = await hashedPassword(newPassword);

    return await db.update(usersTable).set({password: newHashPassword}).where(eq(usersTable.id, userId));

};


export async function createResetPasswordLink({userId}){
    const randomToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(randomToken).digest('hex');

    await db.delete(passwordResetTokensTable).where(eq(passwordResetTokensTable.userId, userId));

    await db.insert(passwordResetTokensTable).values({userId, tokenHash});

    return `${process.env.FRONTEND_URL}/reset-password/${randomToken}`;

}


export async function getResetPasswordToken(token){

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const [data] = await db.select().from(passwordResetTokensTable).where(and(eq(passwordResetTokensTable.tokenHash, tokenHash), gte(passwordResetTokensTable.expiresAt, sql`CURRENT_TIMESTAMP`)));

    return data;

}


export async function clearResetPasswordToken(userId){
    return await db.delete(passwordResetTokensTable).where(eq(passwordResetTokensTable.userId, userId));
}


export async function getUserWithOauthId({provider, email}){
    const [user] = await db
        .select({
            id: usersTable.id,
            name: usersTable.name,
            email: usersTable.email,
            isEmailValid: usersTable.isEmailValid,
            providerAccountId: oauthAccountTable.providerAccountId,
            provider: oauthAccountTable.provider
        })
        .from(usersTable)
        .where(eq(usersTable.email, email))
        .leftJoin(
            oauthAccountTable,
            and(
                eq(oauthAccountTable.provider, provider),
                eq(oauthAccountTable.userId, usersTable.id),
            ),
        );

        console.log(user);

    return user;
};


export async function linkUserWithOauth({userId, provider, providerAccountId}){
    await db.insert(oauthAccountTable).values({userId, provider, providerAccountId});
};


export async function createUserWithOauth({name, email, provider, providerAccountId}){
    const user = await db.transaction(async (tx)=>{
        const [user] = await tx.insert(usersTable).values({email, name,isEmailValid: true,}).$returningId();
        
        await tx.insert(oauthAccountTable).values({provider, providerAccountId, userId: user.id});

        return { id: user.id, name, email, isEmailValid: true, provider, providerAccountId };
    });

    return user;
}