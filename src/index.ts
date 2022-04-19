import { SignatureProvider, Signer, Verifier, createHmacSignatureProvider } from './signature'
import { Token, ParsedToken, createTokenData, parseToken, validateToken } from './token'
import SWAT, { createSWAT } from './swat'

export {
  SignatureProvider,
  Signer,
  Verifier,
  Token,
  ParsedToken,
  createTokenData,
  parseToken,
  validateToken,
  createHmacSignatureProvider,
  createSWAT,
  SWAT
}

export default SWAT
