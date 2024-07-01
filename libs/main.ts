import jwt, { TokenExpiredError} from 'jsonwebtoken';
import type { SignOptions } from 'jsonwebtoken';
import { PayloadArguments, TokenType, VerifyingResponses, WebtokenInitArguments} from '../types/typedefs';
import Crypto from 'crypto'
import { WebtokenError } from './error';

class WebToken {
    private args: WebtokenInitArguments;
    private uuid: string;

    constructor(args: WebtokenInitArguments) {
        this.args = args
        this.uuid = Crypto.randomUUID()
    }

    private expireIn (value: string): number {
        const expire: string = /[0-9]+/g.exec(value)[0];
        const unit: string = /[a-z]+/gi.exec(value)[0];
        const tmap = {
            s: { time: +expire },
            m: { time: 60 * +expire },
            h: { time: Math.pow(60,2) *  +expire},
            d: { time: Math.pow(60,2) * 24 * +expire}
        };
        return tmap[`${unit.toLowerCase()}`].time;
    };
    /**
     * Create auth token based on JWT specification
     * 
     */
    createAuthToken (payload: PayloadArguments, options: SignOptions ): string  {
        try {
            Object.assign(payload, { _type: 'auth_token' })
            return jwt.sign(payload, this.args.tokenSecretKey, {
                expiresIn: this.expireIn(this.args.authTokenAge),
                ...options
            });
        } catch (error: any) {
            throw new WebtokenError(error.message);
        };
    }
    /**
     * Create refresh token based on JWT specification
     * 
     */
    createRefreshToken (payload: PayloadArguments, options: SignOptions): string {
        try {
            Object.assign(payload, { _type: 'refresh_token' });
            return jwt.sign(payload, this.args.refreshSecretKey, {
                expiresIn: this.expireIn(this.args.refreshTokenAge),
                ...options
            });
        } catch (error: any) {
            throw new WebtokenError(error.message);
        }
    }
    /**
     * Verify auth token or refresh token
     * 
     */
    verify (token: string, type: TokenType): VerifyingResponses {
        const secret = {
            ...type === 'AuthToken' && { key: this.args.tokenSecretKey },
            ...type === 'RefreshToken' && { key: this.args.refreshSecretKey }
        };
        let result: any;
        jwt.verify(token, secret.key, (err, decode) => {
            if (err instanceof TokenExpiredError) {
                const errMessage = type === 'AuthToken' ? `Auth token has expired` : `Refresh token has expired`;
                result = {
                    verified: false,
                    details: {
                        reason: errMessage,
                        ...err.expiredAt && { expiredAt: err.expiredAt }
                    }
                }
            };
            if (err instanceof TokenExpiredError === false && err) {
                result = {
                    verified: false,
                    details: err.message
                };
            };
            if (!err) {
                result = {
                    verified: true,
                    details: {
                        // @ts-ignore
                        ...decode._type && { _type: decode._type },
                        // @ts-ignore
                        ...decode.jti && { _id: decode.jti },
                    }
                };
            };
        });
        
        return result;
    }
}

export { WebToken }