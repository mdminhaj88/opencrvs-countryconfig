/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * OpenCRVS is also distributed under the terms of the Civil Registration
 * & Healthcare Disclaimer located at http://opencrvs.org/license.
 *
 * Copyright (C) The OpenCRVS Authors located at https://github.com/opencrvs/opencrvs-core/blob/master/AUTHORS.
 */
import { CLIENT_APP_URL, GATEWAY_URL } from '@countryconfig/constants'
import { env } from '@countryconfig/environment'
import { logger } from '@countryconfig/logger'
import { ServerRoute, ReqRefDefaults } from '@hapi/hapi'
import { createClient } from '@opencrvs/toolkit/api'
import { getBearerToken } from '@countryconfig/utils'
import QRCode from 'qrcode'
import { paperBirthCredentialTemplate } from './paper-birth-credential-template'
import { certifyPaperSignRoute } from './certify-paper-issuer'
import { certifyPaperPdfRoute } from './certify-paper-pdf'

const paperCredentialRoute = {
  method: 'POST',
  path: '/verifiable-credentials/paper-credential',
  handler: async (req) => {
    const pathname = (req.payload as Record<string, string>).pathname
    const match = pathname.match(
      /\/events\/(?:print-certificate\/)?([a-f0-9-]{36})/i
    )
    const eventId = match?.[1]

    if (!eventId) {
      throw new Error('Invalid event ID in pathname')
    }

    if (!req.headers.authorization) {
      throw new Error('Missing authorization header')
    }

    logger.info(
      `[verifiable credentials] requesting paper credential for <event-id:${eventId}>`
    )

    const url = new URL('events', GATEWAY_URL).toString()
    const client = createClient(url, getBearerToken(req.headers.authorization))
    const event = await client.event.search.query({
      query: {
        type: 'and',
        clauses: [
          {
            id: eventId
          }
        ]
      }
    })

    if (!event.results.length) {
      throw new Error(`No event found for id: ${eventId}`)
    }

    const response = await fetch(env.VERIFIABLE_CREDENTIALS_RAW_JWT_SIGN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: getBearerToken(req.headers.authorization)
      },
      body: JSON.stringify(paperBirthCredentialTemplate(event.results[0]))
    })

    if (!response.ok) {
      const errorText = await response.text()
      logger.error(
        `[verifiable credentials] failed to issue paper credential for <event-id:${eventId}>: ${errorText}`
      )
      throw new Error(
        `Failed to issue paper credential: ${response.status} ${errorText}`
      )
    }

    const credentialJwt = (await response.text()).trim().replace(/^"|"$/g, '')

    // The QR payload is a JWT for jwt_vc_json, or the compact claim-169 string
    // for ldp_vc, so only check that something came back.
    if (!credentialJwt) {
      throw new Error('Issuer did not return a credential')
    }

    const paperVcQrDataUrl = await QRCode.toDataURL(credentialJwt, {
      width: 600,
      errorCorrectionLevel: 'L'
    })

    return {
      credential: credentialJwt,
      credential_qr: paperVcQrDataUrl
    }
  }
} satisfies ServerRoute<ReqRefDefaults>

export const PAPER_CREDENTIAL_HANDLER_URL = new URL(
  `api/countryconfig/${paperCredentialRoute.path}`,
  CLIENT_APP_URL
).toString()

/**
 * Paper credentials only:
 *  - paperCredentialRoute    called by the print form; builds the template and QR
 *  - certifyPaperSignRoute   the issuer behind VERIFIABLE_CREDENTIALS_RAW_JWT_SIGN_URL,
 *                            backed by Inji Certify
 *  - certifyPaperPdfRoute    same payload, returns the printable credential PDF
 */
export default function getVerifiableCredentialRoutes(): ServerRoute<ReqRefDefaults>[] {
  return [certifyPaperSignRoute, certifyPaperPdfRoute, paperCredentialRoute]
}
