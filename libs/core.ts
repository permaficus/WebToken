import jwt from 'jsonwebtoken';
import type { SignOptions } from 'jsonwebtoken';
import { PayloadArguments, WebtokenInitArguments} from '../types/typedefs';
import Crypto from 'crypto'

class WebToken {
    private args: WebtokenInitArguments;
    private uuid: string;

    constructor(args: WebtokenInitArguments) {
        this.args = args,
        this.uuid = Crypto.randomUUID();
    }

    private expireIn = (value: string): number => {
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
     * Create authentication or authorization token based on JWT specification
     * 
     *
     */
    createAuthToken = (payload: PayloadArguments, options: SignOptions ): string => {
        Object.assign(payload, { iat: Date.now() })
        return jwt.sign(payload, this.args.tokenSecretKey, {
            expiresIn: this.expireIn(this.args.authTokenAge),
            ...options
        })
    }
    createRefreshToken = (payload: PayloadArguments, options: SignOptions): string => {
        Object.assign(payload, { jti: this.uuid });
        return jwt.sign(payload, this.args.refreshSecretKey, {
            expiresIn: this.expireIn(this.args.refreshTokenAge),
            ...options
        })
    }
}

export default WebToken