import { json } from "body-parser";
import { createHmac, KeyObject, timingSafeEqual } from 'crypto';
import { IncomingMessage } from "http";
import { NextApiRequest, NextApiResponse } from "next";

type ValidatedOptions = Readonly<{
  /**
   * If given, will be used before `keyString`/`keyEnvVar`.
   * 
   * Env vars will override.
   */
  key: Buffer | KeyObject;

  /**
   * A hex-encoded byte array to use as the key for validating.
   */
  keyString?: string;

  /**
   * Defaults to 'VALIDATED_WEBHOOK_KEY'.
   */
  keyEnvVar?: string;

  /**
   * Defaults to HMAC
   */
  headerName?: string;

  /**
   * Defaults to false
   */
  verbose?: boolean;

  /**
   * Defaults to the expected `getURL` function.
   */
  getURL?: (req: IncomingMessage) => string;

  /**
   * Defaults to sha256
   */
  hashAlgo?: 'sha256' | 'sha1'
}>

type ValidatedResult = Readonly<{ digest: Buffer; }>

export function getURL(req: IncomingMessage) {
  var protocol = req.headers["x-forwarded-proto"] || "http:"
  var host = req.headers["x-forwarded-host"] || req.headers["host"]
  return protocol + "//" + host + req.url
}

/**
 * Equivalent to computing:
 * 
 * `hmac(opts.hashAlgo, opts.key, `${req.method}\n${url}\n${req.bodyAsBytes}`)`
 */
export const computeDigest = (opts: ValidatedOptions, req: IncomingMessage, bodyBuf: Buffer) => {
  const url = (opts.getURL || getURL)(req)
  const hmac = createHmac(opts.hashAlgo, opts.key)
  hmac.update(req.method.toUpperCase())
  hmac.update('\n')
  hmac.update(url)
  hmac.update('\n')
  hmac.update(bodyBuf)
  const digest = hmac.digest()

  if (opts.verbose) {
    console.log('Normalised message:')
    console.log('---')
    console.log(req.method.toUpperCase())
    console.log(url)
    console.log(bodyBuf.toString())
    console.log('---')
    console.log('=> ', digest.toString('hex'))
  }

  return digest
}

/**
 * This is the middleware function that parses the JSON and validates input.
 */
const signedJSON = (options: Partial<ValidatedOptions> = {}) => {
  const envName = options.keyEnvVar || 'VALIDATED_WEBHOOK_KEY'
  const fromEnv = process.env[envName] || options.keyString
  const opts: ValidatedOptions = {
    ...options,
    hashAlgo: 'sha256',
    key: options.key || Buffer.from(fromEnv, 'utf8')
  }

  return json({
    verify(req, res, buf, enc) {
      const error = (message: string) => { throw new Error(message) }

      if (opts.verbose) console.log('using shared key', fromEnv)
      
      let actual: Buffer = computeDigest(opts, req, buf)

      const clientSupplied = req.headers[opts.headerName || 'hmac']

      if (clientSupplied == null) return error('Missing "hmac" header from request.')
      if (Array.isArray(clientSupplied)) return error('Only one HMAC value allowed in header "hmac".')

      const clientSuppliedBuf = Buffer.from(clientSupplied, 'hex')

      if (clientSuppliedBuf.length == 0) return error('The "hmac" header did not contain hex-only characters')
      if (clientSuppliedBuf.length !== actual.length) return error('The "hmac" header did not have a value long enough.')
      if (!(timingSafeEqual(actual, clientSuppliedBuf))) {
        if (opts.verbose) {
          console.log('Server expected HMAC=', actual.toString('hex'))
          console.log('Client sent HMAC=', clientSuppliedBuf.toString('hex'))
        }

        return error('The "hmac" header did not match the request hmac of the url+contents.')
      }

      Object.assign(req, { digest: clientSuppliedBuf })
    }
  })
}

const validatedHook = signedJSON({ verbose: true })

// Helper method to wait for a middleware to execute before continuing
// And to throw an error when an error happens in a middleware
function runMiddleware(req, res, middleware) {
  return new Promise((resolve, reject) => {
    middleware(req, res, result => result instanceof Error ? reject(result) : resolve(result))
  })
}

// example usage:
// curl -H "content-type: application/json; charset=utf-8" -XPOST -d '{"hi":"hello"}' http://localhost:3000/api/hello -s | jq .
export default async function hello(req: NextApiRequest & ValidatedResult, res: NextApiResponse) {
  try {
    await runMiddleware(req, res, validatedHook)
  } catch (e) {
    console.error('Request validation failed', e)
    res.status(e.status).json({ error: true, message: e.message })
    return
  }

  res.status(200).json({
    error: false,
    message: 'ok',
    digest: req.digest.toString('hex'),
    bodyType: typeof req.body,
    body: req.body
  })
}

export const config = {
  api: {
    bodyParser: false,
  },
}
