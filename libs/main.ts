import jwt, { JsonWebTokenError} from 'jsonwebtoken';
import type { SignOptions } from 'jsonwebtoken';
import { PayloadArguments, TokenType, VerifyingResponses, WebtokenInitArguments} from '../types/typedefs';
import Crypto from 'crypto'
import {WebtokenError, WebtokenExpiredError} from './error';

class WebToken {
    private args: WebtokenInitArguments;
    private uuid: string;

    constructor(args: WebtokenInitArguments) {
        this.args = args,
        this.uuid = Crypto.randomUUID();
    }

    private expireIn (value: string): number {
        const expire: string = /[0-9]+/g.exec(value)[0];
        const unit: string = /[a-z]+/gi.exec(value)[0];
        const tmap = {
            s: { time: 1000 * +expire },
            m: { time: 1000 * 60 * +expire },
            h: { time: 1000 * Math.pow(60,2) *  +expire},
            d: { time: 1000 * Math.pow(60,2) * 24 * +expire}
        }
        return tmap[`${unit.toLowerCase()}`].time
    }
    /**
     * Create auth token based on JWT specification
     * 
     */
    createAuthToken (payload: PayloadArguments, options: SignOptions ): string  {
        try {
            Object.assign(payload, { iat: Date.now(), _type: 'auth_token' })
            return jwt.sign(payload, this.args.tokenSecretKey, {
                expiresIn: this.expireIn(this.args.authTokenAge),
                ...options
            })
        } catch (error: any) {
            throw new WebtokenError(error.message)
        }
    }
    /**
     * Create refresh token based on JWT specification
     * 
     */
    createRefreshToken (payload: PayloadArguments, options: SignOptions): string {
        try {
            Object.assign(payload, { iat: Date.now(), _type: 'refresh_token' });
            return jwt.sign(payload, this.args.refreshSecretKey, {
                expiresIn: this.expireIn(this.args.refreshTokenAge),
                ...options
            })
        } catch (error: any) {
            throw new WebtokenError(error.message)
        }
    }
    /**
     * Verify auth token or refresh token
     * 
     */
    verify (token: string, type: TokenType): VerifyingResponses | WebtokenExpiredError {
        const secret = {
            ...type === 'AuthToken' && { key: this.args.tokenSecretKey },
            ...type === 'RefreshToken' && { key: this.args.refreshSecretKey }
        }
        let result: VerifyingResponses
        jwt.verify(token, secret.key, (err, decode) => {
            if (err) {
                result = {
                    verified: false
                }
            }
            if (err instanceof jwt.TokenExpiredError) {
                const errMessage = type === 'AuthToken' ? `Auth token has expired` : `Refresh token has expired`;
                return new WebtokenExpiredError(errMessage, err.expiredAt)
            }
            if (!err) {
                result = {
                    verified: true,
                    details: {
                        // @ts-ignore
                        ...decode._type && { _type: decode._type },
                        // @ts-ignore
                        ...decode.jti && { _id: decode.jti }
                    }
                }
            }
        })
        
        return result
    }
}

export { WebToken }