export interface WebtokenInitArguments {
    tokenSecretKey?: string
    refreshSecretKey?: string
    authTokenAge?: string
    refreshTokenAge?: string
}
export type PayloadArguments = {
    aud?: string
    iss?: string
    subj?: string
    jti?: string
} | UserDefinedArguments
export type UserDefinedArguments = {
    [key: string]: string | string[] | object | number | Buffer
}
export interface VerifyingResponses {
    verified: boolean
    reason?: string
    details?: string | object | undefined
}
export type TokenType = 'AuthToken' | 'RefreshToken'