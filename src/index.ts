import { timingSafeEqual } from 'crypto'
import { tokenInfo, createPayload, Algo, createSignature } from './token'

export default class SWAT {
  public readonly tokenInfo = tokenInfo

  constructor(
    private readonly secret: string,
    public readonly algo: Algo = 'sha256'
  ) {}

  public create(type: string, key: string, expires?: number): string {
    const data = createPayload(type, key, expires)

    return `${data}|${this.sign(data)}`
  }

  public verify(token: string): boolean {
    if (token.split('|').length !== 2) {
      return false
    }

    const [data, sign] = token.split('|')

    const [hmacBuffer, signBuffer] = [
      Buffer.from(this.sign(data), 'base64'),
      Buffer.from(sign, 'base64')
    ]

    if (hmacBuffer.length !== signBuffer.length) {
      return false
    }

    if (! timingSafeEqual(hmacBuffer, signBuffer)) {
      return false
    }

    const info = tokenInfo(token)

    if (info.expires && info.expires < Date.now()) {
      return false
    }

    return true
  }

  public sign(payload: string) {
    return createSignature(payload, this.secret, this.algo)
  }
}
