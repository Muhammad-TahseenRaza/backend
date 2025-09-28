import crypto from 'crypto';
import { checkShortCode, deleteShortlink, getShortLinkById, loadLinks, saveLinks, updateShortLink } from '../models/01.shortener.model.js';
import { shortenerSchema, shortenerSearchParamsSchea } from '../validators/01.shortener.validator.js';
import z from 'zod';


export async function getShortenerPage(req, res){

    if(!req.user){ return res.redirect('/login') };
    
    // let links = await loadLinks(req.user.id);

    let searchParams = shortenerSearchParamsSchea.parse(req.query);

    const { links, totalCount } = await loadLinks({userId: req.user.id, limit: 10, offset: (searchParams.page - 1) * 10});

    let totalPages = Math.ceil(totalCount / 10);


    return res.render('index', {links ,currentPage: searchParams.page, totalPages, host: req.host, errors: req.flash('errors')});
};


export async function postShortenerPage(req, res){

    let {data, error} = shortenerSchema.safeParse(req.body);

    if(error){
        let message = error.issues[0].message;
        req.flash('errors', message);
        return res.redirect('/');
    }

    let { url, shortCode } = data;

    if(!url){
        return res.status(400).send('url not found');
    }

    const finalShortCode = shortCode || crypto.randomBytes(4).toString('hex');

    let exists = await checkShortCode(finalShortCode, req.user.id);
    
    if(exists){
        req.flash('errors', 'url already exits');
        return res.redirect('/');
    }

    await saveLinks({finalShortCode, url, userId: req.user.id});

    return res.redirect('/');
}


export async function redirectToLink(req, res){

    let {shortCode} = req.params;
    let exists = await checkShortCode(shortCode, req.user.id);

    if(!exists){
        return res.status(404).render('404');
    }

    return res.redirect(exists.url);
}


export async function getShortenerEditPage(req, res){

    if(!req.user){return res.redirect('/login')};

    let {data: id, error} = z.coerce.number().int().safeParse(req.params.id);

    if(error){ return res.redirect('/404') };

    let shortLink = await getShortLinkById(id);

    if(!shortLink){return res.redirect('/404')};

    return res.render('edit-shortener', {
        id: shortLink.id,
        url: shortLink.url,
        shortCode: shortLink.shortCode,
        errors: req.flash('errors'),
    })

}


export async function postShortenerEditPage(req, res){

    if(!req.user){return res.redirect('/login')};

    let {data: id, error} = z.coerce.number().int().safeParse(req.params.id);  
    
    if(error){ return res.redirect('/404') };

    let {data, error: errors} = shortenerSchema.safeParse(req.body);

    if(errors){
        let message = errors.issues[0].message;
        req.flash('errors', message);
        return res.redirect(`/edit/${id}`);
    }

    let { url, shortCode } = data;

    let exists = await checkShortCode(shortCode, req.user.id);
    
    if(exists){
        req.flash('errors', 'url already exits');
        return res.redirect(`/edit/${id}`);
    }    

    await updateShortLink({id, url, shortCode});

    return res.redirect(`/`);

} 


export async function deleteShortLinks(req, res){

    let {data: id, error} = z.coerce.number().int().safeParse(req.params.id);  
    
    if(error){ return res.redirect('/404') };

    await deleteShortlink(id);

    return res.redirect('/');

}