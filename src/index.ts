import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'
import type { StatusCode } from 'hono/utils/http-status'

type CacheEntry = { userId: string; expiresAt: number }

const verifyCache = new Map<string, CacheEntry>()

const pruneCache = (() => {
  let lastPrune = 0
  return () => {
    const now = Date.now()
    if (now - lastPrune < 60 * 1000) return
    lastPrune = now
    for (const [key, entry] of verifyCache) {
      if (now >= entry.expiresAt) verifyCache.delete(key)
    }
  }
})()

const extractBearerToken = (header: string | undefined): string | null => {
  if (!header) return null
  const match = header.match(/^Bearer\s+(\S+)$/i)
  return match?.[1] ?? null
}

const errorJson = (message: string, status: number) =>
  Response.json(
    { error: { message, type: 'authentication_error', param: null, code: null } },
    { status }
  )

const verifyApiKey = async (
  token: string,
  clerkSecretKey: string
): Promise<{ valid: boolean; userId?: string; error?: string }> => {
  pruneCache()

  const cached = verifyCache.get(token)
  if (cached && Date.now() < cached.expiresAt) {
    return { valid: true, userId: cached.userId }
  }

  try {
    const res = await fetch('https://api.clerk.com/v1/api_keys/verify', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${clerkSecretKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ secret: token })
    })

    if (!res.ok) {
      const body = await res.text().catch(() => '')
      if (res.status === 401 || res.status === 403) return { valid: false, error: 'Invalid API key' }
      if (res.status === 404) return { valid: false, error: 'API key not found' }
      return { valid: false, error: `Clerk verification failed (${res.status}): ${body}` }
    }

    const data = (await res.json()) as { subject?: { id?: string }; user_id?: string }
    const userId = data.subject?.id || data.user_id || 'unknown'

    verifyCache.set(token, { userId, expiresAt: Date.now() + 5 * 60 * 1000 })

    return { valid: true, userId }
  } catch (err) {
    return { valid: false, error: `Clerk verification error: ${err}` }
  }
}

export default new Hono<{ Bindings: Env }>()
  .use('*', async (c, next) => {
    if (!c.env.DISABLE_LOGGER_OUTPUT) return logger()(c, next)
    await next()
  })
  .use('*', secureHeaders({ crossOriginResourcePolicy: 'cross-origin' }))
  .use('*', cors())
  .onError((_, c) => c.text('Internal Server Error', 500))
  .all('*', async (c) => {
    const { env } = c

    const token = extractBearerToken(c.req.header('Authorization'))
    if (!token) return errorJson('Missing or malformed Authorization header. Expected: Bearer <API_KEY>', 401)

    const result = await verifyApiKey(token, env.CLERK_SECRET_KEY)
    if (!result.valid) return errorJson(result.error || 'Invalid API key', 401)

    const reqHeaders = new Headers(c.req.raw.headers)
    reqHeaders.set('Authorization', `Bearer ${env.ROUTER_API_KEY}`)

    const res = await fetch(c.req.url, {
      method: c.req.method,
      headers: reqHeaders,
      body: c.req.raw.body,
      redirect: 'follow'
    })

    const resHeaders = new Headers(res.headers)
    return c.newResponse(res.body, { status: res.status as StatusCode, headers: resHeaders })
  })
