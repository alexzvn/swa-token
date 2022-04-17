import { createHmac } from 'crypto'

export interface InfoSWAT {
  key: string
  type: string
  expires?: number
  signature: string
}

export type Algo = 'sha256'|'sha512'|'sha1'

const hmac = (data: string, secret: string, algo: Algo) => createHmac(algo, secret)
  .update(data)
  .digest('base64')
  .replace(/=/, '')

/**
 * Create token payload
 */
export const createPayload = (type: string, key: string, expires?: number) => {
  if (/:/.test(key) || /:/.test(type)) {
    throw new Error('Type or key cannot contain ":"')
  }

  if (expires && typeof expires !== 'number') {
    throw new Error('Expires must be a number')
  }

  return expires ? `${type}:${key}:${expires}` : `${type}:${key}`
}

/**
 * Create signature from given data
 */
export const createSignature = (data: string, secret: string, algo: Algo) => hmac(data, secret, algo)

/**
 * Get info from token
 */
export const tokenInfo = (token: string): InfoSWAT => {
  const [data, signature] = token.split('|')

  const [type, key, expires] = data.split(':')

  return {
    type,
    key,
    signature,
    expires: expires ? parseInt(expires, 10) : undefined
  }
}
