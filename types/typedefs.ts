export interface WebtokenInitArguments {
    tokenSecretKey?: string
    refreshSecretKey?: string
    authTokenAge?: string
    refreshTokenAge?: string
}
export interface PayloadArguments {
    [key: string]: string | string[] | object | number | Buffer
}
export interface AuthTokenOptions {
    algorithm: string

}
