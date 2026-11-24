import { useEffect, useState } from 'react'

import api from './api'

// The backend decides whether plans are sold in Questiz ("local") or managed on bdren.ai
// ("bdren", BILLING_MODE), so the frontend never needs a rebuild to switch. One request per page load.
const LOCAL = { mode: 'local', manage_url: '', provider_label: '' }
let configPromise = null
let configValue = null

export function getBillingConfig() {
  if (!configPromise) {
    configPromise = api
      .get('/billing/config/')
      .then((response) => {
        configValue = { ...LOCAL, ...response.data }
        return configValue
      })
      .catch(() => {
        configPromise = null
        return LOCAL
      })
  }
  return configPromise
}

export function useBillingConfig() {
  const [config, setConfig] = useState(configValue)

  useEffect(() => {
    let active = true
    getBillingConfig().then((value) => {
      if (active) setConfig(value)
    })
    return () => {
      active = false
    }
  }, [])

  const managedExternally = config?.mode === 'bdren'
  return {
    loaded: Boolean(config),
    managedExternally,
    manageUrl: managedExternally ? config.manage_url : '',
    providerLabel: config?.provider_label || 'bdren.ai',
  }
}
