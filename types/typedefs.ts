import { KeyObject } from "crypto";
export type SecretKey = string | Buffer | KeyObject | { key: string | Buffer; passphrase: string }
export interface WebtokenInitArguments {
    authTokenSecretKey?: string | SecretKey
    refreshSecretKey?: string | SecretKey
    authTokenAge?: string
    refreshTokenAge?: string
    algorithm?: Algorithm | undefined
}
export type PayloadArguments = {
    aud?: string
    iss?: string
    sub?: string
    jti?: string
} | UserDefinedArguments
export type UserDefinedArguments = {
    [key: string]: string | string[] | object | number | Buffer
}
export interface VerifyingResponses {
    verified: boolean
    reason?: string
    details?: string | object | undefined
    claims?: object | undefined
}
export interface WebTokenOptions {
    algorithm?: Algorithm | undefined;
    keyid?: string | undefined;
    expiresIn?: string | number;
    notBefore?: string | number | undefined;
    audience?: string | string[] | undefined;
    subject?: string | undefined;
    issuer?: string | undefined;
    jwtid?: string | undefined;
    mutatePayload?: boolean | undefined;
    noTimestamp?: boolean | undefined;
    header?: JWTHeaders | undefined;
    encoding?: string | undefined;
    allowInsecureKeySizes?: boolean | undefined;
    allowInvalidAsymmetricKeyTypes?: boolean | undefined;
}
export interface JWTHeaders {
    alg: string | Algorithm;
    typ?: string | undefined;
    cty?: string | undefined;
    crit?: Array<string | Exclude<keyof JWTHeaders, "crit">> | undefined;
    kid?: string | undefined;
    jku?: string | undefined;
    x5u?: string | string[] | undefined;
    "x5t#S256"?: string | undefined;
    x5t?: string | undefined;
    x5c?: string | string[] | undefined;
}
export type TokenType = 'AuthToken' | 'RefreshToken'
export type Algorithm = 
    | "HS256"
    | "HS384"
    | "HS512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "ES512"
    | "PS256"
    | "PS384"
    | "PS512";