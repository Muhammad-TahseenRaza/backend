import { Router } from "express";
import { deleteShortLinks, getShortenerEditPage, getShortenerPage, postShortenerEditPage, postShortenerPage, redirectToLink } from "../controllers/01.shortener.controller.js";

const router = Router();

router.route('/').get(getShortenerPage);

router.route('/submit').post(postShortenerPage);

router.route('/:shortCode').get(redirectToLink);

router.route('/edit/:id').get(getShortenerEditPage).post(postShortenerEditPage);

router.route('/delete/:id').post(deleteShortLinks);

export let shortenerRoutes = router;