import { ACCESS_TOKEN_MAX_AGE, REFRESH_TOKEN_MAX_AGE } from "../config/constants.js";
import { checkSessionById, checkUserById, createAccessToken, createRefreshToken, verifyJWTToken } from "../models/02.auth.model.js";

export async function verifyAuthentication(req, res, next){

    let accessToken = req.cookies.Access_Token;
    let refreshToken = req.cookies.Refresh_Token;

    if(!accessToken && !refreshToken){
        req.user = null;
        return next();
    };

    if(accessToken){
         try {
            let decodedToken = verifyJWTToken(accessToken);
            req.user = decodedToken;
            return next();
        } catch (err) {
            console.log("Access token expired/invalid:", err.message);
        }
    };

    if(refreshToken){

        try {

            let decodedToken = verifyJWTToken(refreshToken);
            let session = await checkSessionById(decodedToken.sessionId);

            if (!session || !session.valid) {
                req.user = null;
                return next();
            }

            let user = await checkUserById(session.userId);

            if (!user) {
                req.user = null;
                return next();
            }
            
            const newAccessToken = createAccessToken({
                id: user.id,
                name: user.name,
                email: user.email,
                sessionId: session.id,
            });
        
            const newRefreshToken = createRefreshToken(session.id);

        
            res.cookie('Access_Token', newAccessToken, {
                httpOnly: true,
                secure: true,
                maxAge: ACCESS_TOKEN_MAX_AGE,
            });
        
            res.cookie('Refresh_Token', newRefreshToken, {
                httpOnly: true,
                secure: true,
                maxAge: REFRESH_TOKEN_MAX_AGE,
            });

            let userInfo = {
                id: user.id,
                name: user.name,
                email: user.email,
                isEmailValid: user.isEmailValid,
                sessionId: session.id,
            }

            req.user = userInfo;
            
            return next();

        } catch (error) {
            console.log("Refresh token expired/invalid:", error.message);
            req.user = null;
            return next();
        }
    }

    return next();
}