const gate = document.getElementById('brasa-access')
const form = gate.querySelector('form')
const password = document.getElementById('access-password')
const message = document.getElementById('access-message')
const button = form.querySelector('button')

async function unlock(payload, value) {
  const salt = payload.subarray(0, 16)
  const iv = payload.subarray(16, 28)
  const { subtle } = crypto
  const material = await subtle.importKey('raw', new TextEncoder().encode(value), 'PBKDF2', false, ['deriveKey'])
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  )
  const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, key, payload.subarray(28))
  return JSON.parse(new TextDecoder().decode(decrypted))
}

async function start({ script, css }) {
  const styles = document.createElement('style')
  styles.textContent = css
  document.head.append(styles)

  const moduleUrl = URL.createObjectURL(new Blob([script], { type: 'text/javascript' }))
  try {
    await import(moduleUrl)
    gate.remove()
  } catch (error) {
    styles.remove()
    throw error
  } finally {
    URL.revokeObjectURL(moduleUrl)
  }
}

form.addEventListener('submit', async event => {
  event.preventDefault()
  const value = password.value
  button.disabled = true
  password.disabled = true
  button.textContent = 'Abriendo…'
  message.textContent = ''
  try {
    const response = await fetch('./' + document.documentElement.dataset.demoPayload)
    if (!response.ok) throw new Error('No se pudo descargar la demo.')
    const payload = new Uint8Array(await response.arrayBuffer())
    const data = await unlock(payload, value)
    password.value = ''
    await start(data)
  } catch (error) {
    message.textContent = error.name === 'OperationError'
      ? 'Contraseña incorrecta.'
      : 'No se pudo abrir la demo. Inténtalo de nuevo.'
    password.select()
  } finally {
    button.textContent = 'Ingresar'
    button.disabled = false
    password.disabled = false
    if (gate.isConnected) password.focus()
  }
})
