/*
 * Paper verifiable credential issuer backed by Inji Certify.
 *
 * Drop this file into `src/verifiable-credentials/` of your country config.
 *
 * OpenCRVS (`/verifiable-credentials/paper-credential` in routes.ts) POSTs the
 * paper template payload to VERIFIABLE_CREDENTIALS_RAW_JWT_SIGN_URL and expects
 * a plain-text, 3-part signed JWT back. This route is that endpoint. It runs the
 * OpenID4VCI pre-authorized-code flow against Inji Certify on the registrar's
 * behalf, because there is no wallet to redeem the offer:
 *
 *   1. POST  {certify}/pre-authorized-data        (seed offer with the claims)
 *   2. GET   {certify}/credential-offer-data/{id} (read pre-authorized_code)
 *   3. POST  {certify}/oauth/token                (code -> access token + nonce)
 *   4. POST  {certify}/issuance/credential        (proof JWT -> signed credential)
 *
 * Only Node built-ins are used (Node 22: global fetch, node:crypto).
 */
import type { ReqRefDefaults, ServerRoute } from '@hapi/hapi'
import { constants, generateKeyPairSync, sign } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { env } from '@countryconfig/environment'
import { logger } from '@countryconfig/logger'

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'

// Velocity emits undefined template variables verbatim and Certify signs them.
const PLACEHOLDER = /\$\{[A-Za-z_][A-Za-z0-9_.()[\]]*\}/g

export type PaperSignPayload = {
  credentialData?: {
    type?: string[]
    credentialSubject?: Record<string, unknown>
  }
}

class CertifyError extends Error {
  constructor(
    public code: string,
    message: string
  ) {
    super(`${code}: ${message}`)
  }
}

const b64url = (input: Buffer | string) =>
  Buffer.from(input).toString('base64url')

/**
 * The paper credential is bound to a throwaway key (nobody holds it), so one key
 * per process is enough. Generated lazily to avoid slowing down startup.
 */
let proofKeys: { privateKey: KeyObject; jwk: Record<string, unknown> } | null =
  null
function getProofKeys() {
  if (!proofKeys) {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048
    })
    proofKeys = {
      privateKey,
      jwk: { ...publicKey.export({ format: 'jwk' }), alg: 'RS256', use: 'sig' }
    }
  }
  return proofKeys
}

function makeProofJwt(nonce: string) {
  const { privateKey, jwk } = getProofKeys()
  const header = { alg: 'RS256', typ: 'openid4vci-proof+jwt', jwk }
  const payload = {
    aud: env.CERTIFY_AUDIENCE,
    nonce,
    iss: '',
    iat: Math.floor(Date.now() / 1000)
  }
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`
  const signature = sign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    padding: constants.RSA_PKCS1_PADDING
  })
  return `${signingInput}.${b64url(signature)}`
}

async function certifyRequest<T>(
  code: string,
  path: string,
  init: Parameters<typeof fetch>[1] = {}
): Promise<T> {
  const base = env.CERTIFY_BASE_URL.replace(/\/$/, '')
  const response = await fetch(`${base}${path}`, {
    ...init,
    signal: AbortSignal.timeout(env.CERTIFY_HTTP_TIMEOUT_MS)
  })
  if (!response.ok) {
    const text = await response.text()
    logger.error(
      `[certify] ${code} failed (${response.status}) on ${path}: ${text}`
    )
    throw new CertifyError(code, `Certify returned ${response.status}: ${text}`)
  }
  return (await response.json()) as T
}

function stripNullish(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.filter((v) => v != null).map(stripNullish)
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, v]) => v != null)
        .map(([k, v]) => [k, stripNullish(v)])
    )
  }
  return value
}

function rejectUnresolvedPlaceholders(jwt: string) {
  const [, payload] = jwt.split('.')
  let text = jwt
  try {
    text = Buffer.from(payload, 'base64url').toString('utf8')
  } catch {
    // fall back to scanning the raw string
  }
  const leftovers = [...new Set(text.match(PLACEHOLDER) ?? [])]
  if (leftovers.length) {
    throw new CertifyError(
      'CREDENTIAL_TEMPLATE_UNRESOLVED',
      `unresolved template placeholders: ${leftovers.join(', ')}. Fix the vcTemplate for this credential.`
    )
  }
}

export async function issuePaperCredentialViaCertify(
  claims: Record<string, unknown>,
  credentialTypes: string[]
): Promise<string> {
  // 1. Seed a pre-authorized offer with the claims
  const offer = await certifyRequest<{ credential_offer_uri: string }>(
    'PRE_AUTHORIZED_DATA_FAILED',
    '/pre-authorized-data',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential_configuration_id: env.CERTIFY_PAPER_CONFIG_ID,
        claims,
        expires_in: env.CERTIFY_OFFER_EXPIRES_IN,
        ...(env.CERTIFY_TX_CODE && { tx_code: env.CERTIFY_TX_CODE })
      })
    }
  )
  const offerId = decodeURIComponent(offer.credential_offer_uri)
    .replace(/\/$/, '')
    .split('/')
    .pop()

  // 2. Read the pre-authorized code back
  const offerData = await certifyRequest<{
    grants: Record<string, { 'pre-authorized_code': string }>
  }>('CREDENTIAL_OFFER_FETCH_FAILED', `/credential-offer-data/${offerId}`)
  const preAuthorizedCode = offerData.grants[PRE_AUTH_GRANT]['pre-authorized_code']

  // 3. Exchange the code for an access token
  const token = await certifyRequest<{ access_token: string; c_nonce?: string }>(
    'TOKEN_EXCHANGE_FAILED',
    '/oauth/token',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: PRE_AUTH_GRANT,
        'pre-authorized_code': preAuthorizedCode,
        ...(env.CERTIFY_TX_CODE && { tx_code: env.CERTIFY_TX_CODE })
      })
    }
  )

  // 4. Request the signed credential with a proof of possession
  const credentialResponse = await certifyRequest<{ credential?: unknown }>(
    'CREDENTIAL_ISSUANCE_FAILED',
    '/issuance/credential',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token.access_token}`
      },
      body: JSON.stringify({
        format: env.CERTIFY_PAPER_FORMAT,
        credential_definition: { type: credentialTypes },
        proof: {
          proof_type: 'jwt',
          jwt: makeProofJwt(token.c_nonce ?? '')
        }
      })
    }
  )

  const credential = credentialResponse.credential
  if (typeof credential !== 'string' || credential.split('.').length !== 3) {
    throw new CertifyError(
      'PAPER_CREDENTIAL_NOT_JWT',
      'Certify did not return a compact 3-part JWT. The paper credential configuration must use format jwt_vc_json.'
    )
  }
  rejectUnresolvedPlaceholders(credential)
  return credential
}

/**
 * Takes the output of `paperBirthCredentialTemplate(event)` and returns the signed
 * JWT. Use this from routes.ts to skip the HTTP hop (and the
 * VERIFIABLE_CREDENTIALS_RAW_JWT_SIGN_URL variable) entirely.
 */
export async function issuePaperCredentialFromTemplate(
  template: PaperSignPayload
): Promise<string> {
  const subject = template.credentialData?.credentialSubject
  if (!subject) {
    throw new CertifyError(
      'INVALID_PAYLOAD',
      'credentialData.credentialSubject is required'
    )
  }
  const claims = stripNullish(subject) as Record<string, unknown>
  // Types set in the deployment env win over whatever the template sends.
  const configuredTypes = env.CERTIFY_PAPER_CREDENTIAL_TYPES.split(',')
    .map((t) => t.trim())
    .filter(Boolean)
  const types = configuredTypes.length
    ? configuredTypes
    : (template.credentialData?.type ?? ['VerifiableCredential'])
  logger.info(
    `[certify] issuing paper credential, claim keys: ${Object.keys(claims).join(',')}`
  )
  return issuePaperCredentialViaCertify(claims, types)
}

/**
 * Same path/contract as the demo issuer route, under a different prefix.
 * Point VERIFIABLE_CREDENTIALS_RAW_JWT_SIGN_URL at it. Because it lives on the
 * country-config Hapi server, the registrar token OpenCRVS forwards is
 * authenticated by the server's default auth strategy like any other route.
 */
export const certifyPaperSignRoute = {
  method: 'POST',
  path: '/certify-issuer/raw/jwt/sign',
  handler: async (req, h) => {
    try {
      const jwt = await issuePaperCredentialFromTemplate(
        (req.payload ?? {}) as PaperSignPayload
      )
      return h.response(jwt).type('text/plain')
    } catch (error) {
      if (error instanceof CertifyError) {
        // OpenCRVS logs this body and shows a generic failure to the registrar
        return h
          .response(error.message)
          .code(error.code === 'INVALID_PAYLOAD' ? 422 : 502)
          .type('text/plain')
      }
      throw error
    }
  }
} satisfies ServerRoute<ReqRefDefaults>
