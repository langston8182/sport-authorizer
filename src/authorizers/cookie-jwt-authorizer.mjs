// Lambda Authorizer for HTTP API (payload v2.0)
import * as jose from 'jose';
import {getConfigValue} from "../utils/config.appconfig.mjs";

const ENV = process.env.ENVIRONMENT || "preprod";

const COOKIE_NAME = 'access_token'; // nom du cookie à extraire

let cachedCognitoCfg = null;
let cachedCognitoCfgPromise = null;

async function getCognitoConfig() {
    if (cachedCognitoCfg) return cachedCognitoCfg;
    if (!cachedCognitoCfgPromise) {
        cachedCognitoCfgPromise = (async () => {
            const profileName = "cognito";
            const envCfg = await getConfigValue(profileName, ENV, {});

            // fallback process.env utile en local/tests
            return {
                ENVIRONMENT: ENV,
                COGNITO_DOMAIN: envCfg.COGNITO_DOMAIN || process.env.COGNITO_DOMAIN,
                CLIENT_ID: envCfg.CLIENT_ID || process.env.CLIENT_ID,
                REGION: envCfg.REGION || process.env.REGION,
                USER_POOL_ID: envCfg.USER_POOL_ID || process.env.USER_POOL_ID,
            };
        })();
    }
    cachedCognitoCfg = await cachedCognitoCfgPromise;
    return cachedCognitoCfg;
}

async function getTokenFromEvent(event) {
    const headers = event.headers || {};
    const auth = headers.authorization || headers.Authorization || '';

    if (auth.toLowerCase().startsWith('bearer ')) {
        return auth.slice(7).trim();
    }

    const cookieHeader =
        (Array.isArray(event.cookies) && event.cookies.join('; ')) ||
        headers.cookie || headers.Cookie || '';

    if (cookieHeader) {
        const pieces = cookieHeader.split(';').map(s => s.trim());
        for (const c of pieces) {
            const [k, ...rest] = c.split('=');
            if (k === COOKIE_NAME) return rest.join('=');
        }
    }
    return null;
}

export const handler = async (event) => {
    try {
        const token = await getTokenFromEvent(event);
        if (!token) {
            return { isAuthorized: false, context: { reason: 'missing_token' } };
        }
        const cfgCognito = await getCognitoConfig();
        const { USER_POOL_ID, REGION, CLIENT_ID } = cfgCognito;
        const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
        const JWKS = jose.createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));
        // Verify JWT
        const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS, {
            issuer: ISSUER,
            // access_token cognito n’a pas toujours "aud"; si tu veux le vérifier, décommente:
            // audience: AUDIENCE ? [AUDIENCE] : undefined,
        });

        const aud = payload.client_id || '';
        if (!aud || CLIENT_ID && aud !== CLIENT_ID) {
            return { isAuthorized: false, context: { reason: 'invalid_audience' } };
        }


        // Optionnel: contrôles métiers
        if (payload.token_use && payload.token_use !== 'access') {
            return { isAuthorized: false, context: { reason: 'not_access_token' } };
        }

        // OK
        return {
            isAuthorized: true,
            context: {
                sub: payload.sub || '',
                scope: payload.scope || '',
                username: payload.username || '',
                // tu peux propager d’autres claims ici
            },
        };
    } catch (e) {
        console.error('Authorizer error:', e);
        return { isAuthorized: false, context: { reason: 'jwt_invalid' } };
    }
};