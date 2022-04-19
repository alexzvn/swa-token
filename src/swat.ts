import { createTokenData, parseToken, validateToken } from './token'
import { createHmacSignatureProvider, SignatureProvider } from "./signature"

export type Algo = 'none' | 'HS384' | 'HS512' | 'HS256'

export default class SWAT {
  protected providers: { [algo: string]: SignatureProvider } = {}

  protected algo: string = '';

  public readonly parse = parseToken

  constructor(secret: string) {
    this.use('HS384', createHmacSignatureProvider(secret, 'sha384'))
    this.use('HS512', createHmacSignatureProvider(secret, 'sha512'))
    this.use('HS256', createHmacSignatureProvider(secret, 'sha256'))
  }

  public create(subject: string, issuer?: string, expires_at?: number): string {
    const data = createTokenData({
      name: 'swat',
      algo: this.algo,
      subject,
      issuer,
      issued_at: Math.floor(Date.now() / 1000),
      expires_at,
    })

    return `${data}.${this.provider.sign(data)}`
  }

  public verify(_token: string): boolean {
    if (! validateToken(_token)) {
      return false;
    }

    const token = parseToken(_token)

    if (! this.provider) {
      throw new Error(`Can't verify token with algo ${token.algo}`)
    }

    return this.provider.verify(createTokenData(token), token.signature)
  }

  public use(algo: string, provider?: SignatureProvider) {
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
