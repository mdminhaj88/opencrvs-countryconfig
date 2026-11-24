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
import { bool, cleanEnv, num, port, str, url } from 'envalid'

export const env = cleanEnv(process.env, {
  DOMAIN: str({ devDefault: '*' }),
  GATEWAY_URL: url({ devDefault: 'http://localhost:7070' }),
  VERIFIABLE_CREDENTIALS_RAW_JWT_SIGN_URL: url({
    default: 'http://countryconfig:3040/certify-issuer/raw/jwt/sign',
    devDefault: 'http://localhost:3040/certify-issuer/raw/jwt/sign',
    desc: 'URL for signing raw JWTs for verifiable credentials issuance'
  }),
  CERTIFY_BASE_URL: url({
    devDefault: 'http://localhost:8090/v1/certify',
    desc: 'Inji Certify base URL (the part before /pre-authorized-data)'
  }),
  CERTIFY_AUDIENCE: str({
    devDefault: 'http://localhost:8090/v1/certify',
    desc: 'aud claim of the OpenID4VCI proof JWT (Certify credential issuer identifier)'
  }),
  CERTIFY_PAPER_CONFIG_ID: str({
    default: 'CrvsBirthPaperCredential',
    desc: 'Certify credential_config_key_id of the paper birth credential'
  }),
  CERTIFY_PAPER_FORMAT: str({
    default: 'ldp_vc',
    desc: 'Credential format of that configuration: ldp_vc (claim-169 QR) or jwt_vc_json'
  }),
  CERTIFY_PAPER_CONTEXT: str({
    default: 'https://www.w3.org/2018/credentials/v1',
    desc: 'ldp_vc only: comma separated JSON-LD contexts, as in the Certify configuration'
  }),
  CERTIFY_PAPER_QR_CLAIM_PATH: str({
    default: 'claim169.qrCode',
    desc: 'ldp_vc only: path in the issued credential holding the compact QR payload'
  }),
  CERTIFY_PAPER_CREDENTIAL_TYPES: str({
    default: '',
    desc: 'Comma separated credential types requested from Certify. If empty, the type sent by the paper template is used.'
  }),
  CERTIFY_OFFER_EXPIRES_IN: num({ default: 600 }),
  // Must stay below the 10000 ms timeout of the print form HTTP field.
  CERTIFY_HTTP_TIMEOUT_MS: num({ default: 8000 }),
  CERTIFY_TX_CODE: str({
    default: '',
    desc: 'Only if your Certify config requires a tx_code. Leave empty otherwise.'
  }),
  LOGIN_URL: url({ devDefault: 'http://localhost:3020/' }),
  CLIENT_APP_URL: url({ devDefault: 'http://localhost:3000/' }),
  COUNTRY_CONFIG_HOST: str({ default: '0.0.0.0' }),
  COUNTRY_CONFIG_PORT: port({ default: 3040 }),
  AUTH_URL: url({ devDefault: 'http://localhost:4040' }),
  COUNTRY_CONFIG_URL: url({ devDefault: 'http://localhost:3040' }),
  TWO_FA_ENABLED: bool({ default: true }),
  OPENCRVS_ENVIRONMENT: str({ devDefault: 'development' }),
  EVENTS_URL: url({ devDefault: 'http://localhost:5555/' }),
  ANALYTICS_DATABASE_URL: url({
    devDefault:
      'postgres://events_analytics:analytics_password@localhost:5432/events',
    desc: 'The database URL for reads and writes to `analytics.events`. See `/infrastructure/postgres/setup-analytics.sh` for how the default database is set up for your country.'
  }),
  TELEMETRY_ENABLED: bool({
    default: false,
    desc: 'When true, usage telemetry received from the events service is forwarded to the OpenCRVS status service.'
  }),
  COUNTRY_CODE: str({
    default: 'IND',
    desc: 'ISO-style country code of this instance, reported with telemetry.'
  }),
  ENVIRONMENT_NAME: str({
    default: 'development',
    desc: 'Environment name (e.g. "production", "staging") reported as the telemetry environment.'
  }),
  ORGANISATION: str({
    default: 'mdminhaj88',
    desc: 'Organisation running this instance, reported with telemetry. Empty by default.'
  })
})
