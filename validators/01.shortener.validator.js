import z from 'zod';

export const shortenerSchema = z.object({
    url: z.string().url({message: 'Enter a valid url'}),
    shortCode: z.string().trim().min(3, {message: 'shortCode at least 3 char long'}).max(25, {message: 'shortCode is no longer than 25 char'}),
});


export const shortenerSearchParamsSchea = z.object({
    page: z.coerce.number().int().positive().min(1).optional().default(1).catch(1),
})