/*
 * Paper credential PDF, built from the Inji Certify output.
 *
 * Drop next to `certify-paper-issuer.ts` (the file that talks to Certify).
 *
 *   POST /certify-issuer/paper/pdf   same body as /certify-issuer/raw/jwt/sign
 *   -> 200 application/pdf           (printable card with the QR)
 *
 * Flow: issuePaperCredentialFromTemplate() gets the signed credential from
 * Certify (pre-authorized-code flow) -> toQrText() makes it QR-ready with
 * PixelPass -> QR PNG -> one-page PDF via pdf-lib.
 *
 * PixelPass framing (must match what the verifier unwraps, see
 * `decode` in agent-ui/src/app/verify/qr-reader.ts):
 *   - claim-169 / ldp_vc: Certify already returns Base45(zlib(hex-CWT)). It is
 *     QR-ready as is. Encoding it again would double-wrap it and the verifier
 *     would then fail with ERR_INVALID_HEX.
 *   - compact JWT / SD-JWT: too long for a raw QR, so it is compressed with
 *     PixelPass generateQRData() (zlib + Base45).
 *
 * Dependencies: @injistack/pixelpass, qrcode, pdf-lib
 *   npm i @injistack/pixelpass qrcode pdf-lib && npm i -D @types/qrcode
 */
import type { ReqRefDefaults, ServerRoute } from '@hapi/hapi'
import { generateQRData } from '@injistack/pixelpass'
import QRCode from 'qrcode'
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib'
import { logger } from '@countryconfig/logger'
import {
  issuePaperCredentialFromTemplate,
  type PaperSignPayload
} from './certify-paper-issuer'

const TITLE = process.env.CERTIFY_PDF_TITLE ?? 'Verifiable Credential'
const ISSUER = process.env.CERTIFY_PDF_ISSUER_NAME ?? ''

// compact JWT (3 parts) or SD-JWT (JWT~disclosure~...~)
const COMPACT_JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(~[A-Za-z0-9_-]*)*$/

/** The string that is actually drawn as the QR. */
export function toQrText(certifyOutput: string): string {
  return COMPACT_JWT.test(certifyOutput)
    ? generateQRData(certifyOutput)
    : certifyOutput
}

async function qrPng(text: string): Promise<Buffer> {
  // L: the payload is already dense, higher ECC would push past the QR limit.
  return QRCode.toBuffer(text, {
    type: 'png',
    errorCorrectionLevel: 'L',
    margin: 2,
    scale: 6
  })
}

/** Flatten credentialSubject into printable "label: value" rows. */
function toRows(subject: Record<string, unknown>): [string, string][] {
  const rows: [string, string][] = []
  const walk = (node: unknown, path: string) => {
    if (node == null || node === '') return
    if (Array.isArray(node)) {
      if (node.every((v) => v === null || typeof v !== 'object')) {
        rows.push([path, node.join(', ')])
      } else {
        node.forEach((v, i) => walk(v, `${path}[${i + 1}]`))
      }
    } else if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) walk(v, path ? `${path}.${k}` : k)
    } else {
      rows.push([path, String(node)])
    }
  }
  walk(subject, '')
  return rows.filter(([k]) => k && k !== 'id')
}

const label = (k: string) =>
  k
    .replace(/[._]/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/^\w/, (c) => c.toUpperCase())

export async function renderPaperCredentialPdf(args: {
  claims: Record<string, unknown>
  qrText: string
}): Promise<Uint8Array> {
  const pdf = await PDFDocument.create()
  const page = pdf.addPage([595.28, 841.89]) // A4
  const font = await pdf.embedFont(StandardFonts.Helvetica)
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold)
  const { width, height } = page.getSize()
  const margin = 50

  // Standard PDF fonts are WinAnsi only; drawing anything else throws.
  const safe = (f: typeof font, s: string) =>
    [...s].map((c) => { try { f.encodeText(c); return c } catch { return '?' } }).join('')

  let y = height - margin
  page.drawText(safe(bold, TITLE), { x: margin, y, size: 20, font: bold })
  y -= 18
  if (ISSUER) {
    page.drawText(safe(font, `Issued by ${ISSUER}`), {
      x: margin, y, size: 10, font, color: rgb(0.35, 0.35, 0.35)
    })
    y -= 10
  }
  page.drawLine({
    start: { x: margin, y: y - 6 }, end: { x: width - margin, y: y - 6 },
    thickness: 0.8, color: rgb(0.8, 0.8, 0.8)
  })
  y -= 30

  for (const [k, v] of toRows(args.claims)) {
    if (y < margin + 20 + 240 + 40) break // keep room for the QR
    page.drawText(safe(bold, `${label(k)}:`), { x: margin, y, size: 10, font: bold })
    page.drawText(safe(font, v).slice(0, 80), { x: margin + 170, y, size: 10, font })
    y -= 17
  }

  const img = await pdf.embedPng(await qrPng(args.qrText))
  const size = 240
  const qy = Math.max(y - 20 - size, margin + 20)
  page.drawImage(img, { x: (width - size) / 2, y: qy, width: size, height: size })
  page.drawText('Scan the QR to verify this credential offline.', {
    x: (width - font.widthOfTextAtSize('Scan the QR to verify this credential offline.', 9)) / 2,
    y: margin, size: 9, font, color: rgb(0.35, 0.35, 0.35)
  })

  return pdf.save()
}

export async function issuePaperCredentialPdf(
  template: PaperSignPayload
): Promise<Uint8Array> {
  const certifyOutput = await issuePaperCredentialFromTemplate(template)
  const claims = (template.credentialData?.credentialSubject ?? {}) as Record<string, unknown>
  return renderPaperCredentialPdf({ claims, qrText: toQrText(certifyOutput) })
}

export const certifyPaperPdfRoute = {
  method: 'POST',
  path: '/certify-issuer/paper/pdf',
  handler: async (req, h) => {
    try {
      const bytes = await issuePaperCredentialPdf((req.payload ?? {}) as PaperSignPayload)
      return h
        .response(Buffer.from(bytes))
        .type('application/pdf')
        .header('Content-Disposition', 'attachment; filename="credential.pdf"')
    } catch (error) {
      const message = (error as Error).message
      logger.error(`[certify-pdf] ${message}`)
      const invalid = message.startsWith('INVALID_PAYLOAD')
      return h.response(message).code(invalid ? 422 : 502).type('text/plain')
    }
  }
} satisfies ServerRoute<ReqRefDefaults>
