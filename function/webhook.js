exports.handler = async (event) => {
  const webhook = process.env.DISCORD_WEBHOOK_URL
  const token = process.env.WEBHOOK_TOKEN
  if (!webhook) return { statusCode: 500, body: 'No webhook configured' }
  if (token && event.headers['x-webhook-token'] !== token) {
    return { statusCode: 401, body: 'Unauthorized' }
  }
  let body = {}
  try { body = JSON.parse(event.body || '{}') } catch (e) { body = {} }
  const payload = { content: body.content || '' }
  try {
    const resp = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    const text = await resp.text()
    return { statusCode: resp.ok ? 200 : resp.status, body: text }
  } catch (err) {
    return { statusCode: 500, body: String(err) }
  }
}
