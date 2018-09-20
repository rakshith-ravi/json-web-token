export interface JWTError extends Error {
	constructor(message: string): JWTError;
}

export interface JWTResult {
	payload: any;
	header: any;
}

export function encode(secret: string | Buffer | NodeJS.TypedArray | DataView, payload: any, header: any): Promise<string>;
export function encode(secret: string | Buffer | NodeJS.TypedArray | DataView, payload: any): Promise<string>;

export function encode(secret: string | Buffer | NodeJS.TypedArray | DataView, payload: any, header: any, callback: (err: JWTError, token?: string) => void) : void;
export function encode(secret: string | Buffer | NodeJS.TypedArray | DataView, payload: any, callback: (err: JWTError, token?: string) => void): void;

export function decode(secret: string | Buffer | NodeJS.TypedArray | DataView, token: string, callback?: (err: JWTError, result?: JWTResult) => void): Promise<JWTResult>;

export function getAlgorithms(): string[];