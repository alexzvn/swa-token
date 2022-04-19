export interface Token {
  /**
   * Name of the token
   */
  name: string

  /**
   * Algorithm used to create the signature
   */
  algo: string

  issuer?: string

  subject?: string

  /**
   * Timestamp seconds
   */
  issued_at: number

  /**
   * Timestamp seconds
   */
  expires_at?: number
}

export interface ParsedToken extends Token {
  signature?: string
}

/**
 * 
 * @param token 
 * @returns token without signature
 */
export const createTokenData = (token: Token): string => {
  const head = `${token.name}:${token.algo}`

  const payload = `${token.issuer || ''}:${token.subject || ''}:${token.issued_at}:${token.expires_at || ''}`

  return `${head}.${payload}`
}

export const parseToken = (token: string): ParsedToken => {
  const [head, payload, signature] = token.split('.')

  const [name, algo] = head.split(':')

  const [issuer, subject, issued_at, expires_at] = payload.split(':')

  return {
    name,
    algo,

    issuer,
    subject,
    issued_at: parseInt(issued_at, 10),
    expires_at: parseInt(expires_at, 10),

    signature,
  }
}

export const validateToken = (token: string) => {
  const [head, body] = token.split('.')

  if (!head || !body) {
    return false
  }

  if (head.split(':').length !== 2) {
    return false
  }

  if (body.split(':').length < 4) {
    return false
  }

  return true
}
