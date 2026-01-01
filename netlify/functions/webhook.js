

exports.handler = async function (event, context) {

  const TOKEN = process.env.WEBHOOK_TOKEN

  const headerToken = (event.headers['x-webhook-token'] || event.headers['X-Webhook-Token'] || '').toString()
  if (!TOKEN || headerToken !== TOKEN) {
    return {

      const crypto = require('crypto')

      exports.handler = async function (event, context) {

        const TOKEN = process.env.WEBHOOK_TOKEN

        if (!TOKEN || !DISCORD_WEBHOOK) {
          return { statusCode: 500, body: 'Server misconfigured' }
        }

        const headers = {}
        for (const k in event.headers || {}) {
          headers[k.toLowerCase()] = event.headers[k]
        }

        const headerToken = headers['x-webhook-token'] || ''
        const tsHeader = headers['x-timestamp'] || ''
        const sigHeader = headers['x-signature'] || ''

        if (headerToken !== TOKEN) {
          return { statusCode: 401, body: 'Unauthorized: invalid token' }
        }

        const now = Math.floor(Date.now() / 1000)
        const ts = parseInt(tsHeader, 10)
        if (!ts || Math.abs(now - ts) > 60) {
          return { statusCode: 400, body: 'Invalid or stale timestamp' }
        }

        if (sigHeader) {
          try {
            const payload = `${tsHeader}.${event.body || ''}`
            const expected = crypto.createHmac('sha256', TOKEN).update(payload).digest('hex')
            const a = Buffer.from(expected, 'hex')
            const b = Buffer.from(sigHeader, 'hex')
            if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
              return { statusCode: 401, body: 'Invalid signature' }
            }
          } catch (e) {
            return { statusCode: 400, body: 'Signature verification error' }
          }
        }

        try {
          const res = await fetch(DISCORD_WEBHOOK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: event.body
          })
          const text = await res.text()
          return { statusCode: res.status, body: text }
        } catch (err) {
          return { statusCode: 502, body: 'Forwarding error: ' + String(err) }
        }
      }



