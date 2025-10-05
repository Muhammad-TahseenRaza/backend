import crypto from "crypto";
if (!globalThis.crypto) {
  globalThis.crypto = crypto.webcrypto;
}
import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import flash from 'connect-flash';
import requestIp from 'request-ip';

import { env } from './config/env.js';
import { shortenerRoutes } from './routes/01.shortener.routes.js';
import { authRoutes } from './routes/02.auth.routes.js';
import { verifyAuthentication } from './middlewares/01.auth.middleware.js';

const app = express();

app.use(express.static('public'));

app.use(express.urlencoded());

app.use(cookieParser());

app.use(session({secret: 'asdf', resave: true, saveUninitialized: false}));
app.use(flash());

app.use(verifyAuthentication);
app.use((req, res, next)=>{
    res.locals.user = req.user;
    return next();
});

app.use(requestIp.mw());

app.set('view engine', 'ejs');


app.use(authRoutes);
app.use(shortenerRoutes);


const PORT = env.PORT;

app.listen(PORT, ()=>{
    console.log(`http://localhost:${PORT}`);
})