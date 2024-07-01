import { TokenExpiredError } from 'jsonwebtoken';
class WebtokenError extends Error {
    constructor(message: string) {
        super(message)
        this.name = this.constructor.name

        Object.setPrototypeOf(this, WebtokenError.prototype)
    }
}
class WebtokenExpiredError extends TokenExpiredError {
    constructor(message: string, expiredAt: Date) {
        super(message, expiredAt)
        this.name = this.constructor.name

        Object.setPrototypeOf(this, WebtokenExpiredError.prototype)
    }
}

export { WebtokenError, WebtokenExpiredError }