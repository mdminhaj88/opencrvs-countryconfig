// PixelPass ships no type declarations.
declare module '@injistack/pixelpass' {
  /** zlib + Base45: compact string -> QR-ready string. */
  export function generateQRData(data: string, ecc?: string, header?: string): string
  /** Base45(zlib(hex)) -> hex. */
  export function decode(data: string): string
}
