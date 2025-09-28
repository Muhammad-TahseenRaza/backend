import fs from 'fs/promises';
import mjml2html from 'mjml';
import path from 'path';
import ejs from 'ejs';

export async function getHtmlFromMjmlTemplate(template, data){

    const mjmlTemplate = await fs.readFile(path.join(import.meta.dirname, '..', 'email', `${template}.mjml`), 'utf-8');

    const filledTemplate = ejs.render(mjmlTemplate, data);

    return mjml2html(filledTemplate).html;

}