class WebtokenError extends Error {
    constructor(message: string) {
        super(message)
        this.name = this.constructor.name

        Object.setPrototypeOf(this, WebtokenError.prototype)
    }
}

export { WebtokenError }