import { int, mysqlTable, varchar, timestamp, unique, boolean, text, mysqlEnum } from 'drizzle-orm/mysql-core';
import { relations, sql } from "drizzle-orm";

export const shortLinks = mysqlTable('short_links', {
    id: int().autoincrement().primaryKey(),
    shortCode: varchar({ length: 20 }).notNull(),
    url: varchar({ length: 255 }).notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().onUpdateNow().notNull(),
    userId: int('user_id').notNull().references(() => usersTable.id, { onDelete: 'cascade' }),
}, (table) => {
    return {
        userShortCodeUnique: unique().on(table.userId, table.shortCode),
    }
});


export const sessionsTable = mysqlTable('sessions', {
    id: int().autoincrement().primaryKey(),
    userId: int('user_id').notNull().references(() => usersTable.id, { onDelete: 'cascade' }),
    valid: boolean().default(true).notNull(),
    userAgent: text('user_agent'),
    ip: varchar({ length: 255 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().onUpdateNow().notNull(),
})


export const emailVerifications = mysqlTable('is_email_valid', {
    id: int().autoincrement().primaryKey(),
    userId: int('user_id').notNull().references(() => usersTable.id, { onDelete: 'cascade' }),
    token: varchar({ length: 255 }).notNull(),
    expiresAt: timestamp('expires_at').default(sql`(CURRENT_TIMESTAMP + INTERVAL 1 DAY)`).notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
});


export const passwordResetTokensTable = mysqlTable('password_reset_tokens', {
    id: int('id').autoincrement().primaryKey(),
    userId: int('user_id').notNull().references(()=> usersTable.id, {onDelete: 'cascade'}).unique(),
    tokenHash: text('token_hash').notNull(),
    expiresAt: timestamp('expires_at').default(sql`(CURRENT_TIMESTAMP + INTERVAL 1 HOUR)`).notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
});


export const oauthAccountTable = mysqlTable('oauth_accounts', {
    id: int('id').autoincrement().primaryKey(),
    userId: int('user_id').notNull().references(()=> usersTable.id, {onDelete: 'cascade'}),
    provider: mysqlEnum('provider', ['google', 'github']).notNull(),
    providerAccountId: varchar('provider_account_id', {length: 255}).notNull().unique(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
});


export const usersTable = mysqlTable('users', {
    id: int().autoincrement().primaryKey(),
    name: varchar({ length: 255 }).notNull(),
    email: varchar({ length: 255 }).notNull().unique(),
    avatarUrl: text('avatar_url'),
    isEmailValid: boolean('is_email_valid').default(false).notNull(),
    password: varchar({ length: 255 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().onUpdateNow().notNull(),
});


export const usersRelation = relations(usersTable, ({ many }) => ({
    shortLink: many(shortLinks),
    session: many(sessionsTable),
}));

export const shortLinksRelation = relations(shortLinks, ({ one }) => ({
    user: one(usersTable, {
        fields: [shortLinks.userId],
        references: [usersTable.id],
    }),
}));

export const sessionsRelation = relations(sessionsTable, ({ one }) => ({
    user: one(usersTable, {
        fields: [sessionsTable.userId],
        references: [usersTable.id],
    })
}))