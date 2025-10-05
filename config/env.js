import z from 'zod';
import dotenv from "dotenv";
dotenv.config();

let portSchema = z.object({
    PORT: z.coerce.number().default(3002),
    DATABASE_URL: z.string(),
});

export let env = portSchema.parse(process.env);