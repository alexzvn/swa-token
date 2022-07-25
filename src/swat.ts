import { createTokenData, parseToken, validateToken } from './token'
import { createHmacSignatureProvider, SignatureProvider } from "./signature"

export type Algo = 'HS256' | 'HS384' | 'HS512' | String

export const createSWAT = (secret: string): SWAT => {
  const hmac = (algo: string) => createHmacSignatureProvider(secret, algo)

  const swat = new SWAT()

  swat.use('HS384', hmac('sha384'))
  swat.use('HS512', hmac('sha512'))
  swat.use('HS256', hmac('sha256'))

  return swat
}

export default class SWAT {
  protected providers: { [algo: string]: SignatureProvider } = {}

  protected algo: string = 'none'

  public readonly parse = parseToken

  constructor() {}

  public create(subject: string, issuer?: string, expires_at?: number, issued_at?: number): string {
    const data = createTokenData({
      name: 'swat',
      algo: this.algo,
      subject,
      issuer,
      issued_at: issued_at || Math.floor(Date.now() / 1000),
      expires_at,
    })

    return `${data}.${this.provider.sign(data)}`
  }

  public verify(_token: string, issuer?: string): boolean {
    if (! validateToken(_token)) {
      return false;
    }

    const token = parseToken(_token)

    if (token.expires_at && token.expires_at < Math.floor(Date.now() / 1000)) {
      return false;
    }

    if (issuer && issuer !== token.issuer) {
      return false
    }

    if (! this.provider) {
      throw new Error(`Can't verify token with algo ${token.algo}`)
    }

    return this.provider.verify(createTokenData(token), token.signature)
  }

  public use(algorithm: Algo, provider?: SignatureProvider) {
    const algo = algorithm.toString()

    if (provider) {
      this.providers[algo] = provider
    }

    this.algo = algo

    if (! this.providers[algo]) {
      throw new Error(`Signature provider for ${algo} not found`)
    }

    return this
  }

  get provider(): SignatureProvider {
    return this.providers[this.algo]
  }
}
