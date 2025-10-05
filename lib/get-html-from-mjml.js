import fs from 'fs/promises';
import mjml2html from 'mjml';
import path from 'path';
import ejs from 'ejs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export async function getHtmlFromMjmlTemplate(template, data){

    const mjmlTemplate = await fs.readFile(path.join(__dirname, '..', 'email', `${template}.mjml`), 'utf-8');

    const filledTemplate = ejs.render(mjmlTemplate, data);

    return mjml2html(filledTemplate).html;

}