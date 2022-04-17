import { createHmac } from 'crypto'

export interface InfoSWAT {
  key: string
  type: string
  issue_at: number
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

  const payload = `${type}:${key}:${Date.now()}`

  return expires ? `${payload}:${expires}` : payload
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

  const [type, key, issue_at, expires] = data.split(':')

  return {
    type,
    key,
    signature,
    issue_at: parseInt(issue_at, 10),
    expires: expires ? parseInt(expires, 10) : undefined
  }
}
