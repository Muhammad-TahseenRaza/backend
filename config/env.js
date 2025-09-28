import z from 'zod';

let portSchema = z.object({
    PORT: z.coerce.number().default(3002),
    DATABASE_URL: z.string(),
});

export let env = portSchema.parse(process.env);