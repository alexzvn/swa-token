import { createHmac, timingSafeEqual } from 'crypto'

export interface Signer {
  (data: string): string;
}

export interface Verifier {
  (data: string, signature?: string): boolean;
}

export interface SignatureProvider {
  sign: Signer
  verify: Verifier
}

export const createHmacSignatureProvider = (secret: string, algo: string): SignatureProvider => {
  const sign = (data: string): string => createHmac(algo, secret)
    .update(data)
    .digest('base64')
    .replace(/=+/, '')

  const verify = (data: string, signature?: string): boolean => {
    const computedSignature = sign(data)

    if (! signature) {
      return false
    }

    if (computedSignature.length !== signature.length) {
      return false
    }

    return timingSafeEqual(Buffer.from(signature), Buffer.from(computedSignature))
  }

  return { sign, verify }
}
