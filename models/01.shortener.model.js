import { eq, and, desc, count } from 'drizzle-orm';
import { db } from '../config/drizzle.js';
import { shortLinks } from '../drizzle/schema.js';

export async function loadLinks({userId, limit = 10, offset = 0}) {
    let links = await db.select().from(shortLinks).where(eq(shortLinks.userId, userId)).orderBy(desc(shortLinks.createdAt)).limit(limit).offset(offset);

    const [{totalCount}] = await db.select({totalCount: count()}).from(shortLinks).where(eq(shortLinks.userId, userId));

    return {links, totalCount};
}

export async function checkShortCode(finalShortCode, userId) {
    let [link] = await db.select().from(shortLinks).where(and(
        eq(shortLinks.shortCode, finalShortCode),
        eq(shortLinks.userId, userId)
    ));
    return link;
}

export async function saveLinks({ finalShortCode, url, userId }) {
    await db.insert(shortLinks).values({ shortCode: finalShortCode, url, userId });
}

export async function getShortLinkById(id){
    let [result] = await db.select().from(shortLinks).where(eq(shortLinks.id, id));
    return result;
}

export async function updateShortLink({id, url, shortCode}){
    return await db.update(shortLinks).set({url, shortCode}).where(eq(shortLinks.id , id));
}

export async function deleteShortlink(id){
    return await db.delete(shortLinks).where(eq(shortLinks.id, id));
}