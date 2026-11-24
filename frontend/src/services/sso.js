import api, { API_URL } from './api'

// The backend decides whether single sign-on is on (SSO_ENABLED), so the frontend
// never needs a rebuild to switch it. One request per page load.
let configPromise = null

const DISABLED = { enabled: false, label: '', allow_signup: false }

export function getSsoConfig() {
  if (!configPromise) {
    configPromise = api
      .get('/auth/sso/config/')
      .then((response) => ({ ...DISABLED, ...response.data }))
      .catch(() => {
        configPromise = null
        return DISABLED
      })
  }
  return configPromise
}

// Full-page navigation: the provider's sign-in page cannot run inside an XHR.
export function startSsoLogin(next) {
  const params = new URLSearchParams()
  if (next) {
    params.set('next', next)
  }
  const query = params.toString()
  window.location.assign(`${API_URL}/auth/sso/login/${query ? `?${query}` : ''}`)
}

export async function startSsoLink() {
  const response = await api.post('/auth/sso/link/', {})
  const params = new URLSearchParams({ link_token: response.data.link_token })
  window.location.assign(`${API_URL}/auth/sso/login/?${params.toString()}`)
}

export async function unlinkSso() {
  const response = await api.post('/auth/sso/unlink/', {})
  return response.data
}

const ERROR_MESSAGES = {
  provider_error: 'The sign-in service did not respond as expected. Please try again.',
  state_mismatch: 'Your sign-in session expired. Please start again.',
  invalid_token: 'We could not verify your sign-in. Please try again.',
  email_unverified: 'Your email address is not verified yet. Verify it, then try again.',
  email_in_use:
    'An account with this email already exists. Sign in with your password, then link your account from your profile.',
  signup_disabled: 'No account is linked to this sign-in yet. Sign in with your password and link it from your profile.',
  account_disabled: 'This account is disabled.',
  identity_linked_elsewhere: 'That account is already linked to a different user.',
  already_linked: 'Your account is already linked.',
  link_expired: 'The link request expired. Please try again.',
  session: 'Your sign-in could not be completed. Please try again.',
}

export function ssoErrorMessage(code) {
  if (!code) {
    return ''
  }
  return ERROR_MESSAGES[code] || ERROR_MESSAGES.session
}
