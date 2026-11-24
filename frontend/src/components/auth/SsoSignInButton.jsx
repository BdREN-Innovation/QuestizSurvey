import { useEffect, useState } from 'react'
import { KeyRound } from 'lucide-react'

import { getSsoConfig, startSsoLogin } from '@/services/sso'

// "Continue with <provider>" plus an "or" divider. Renders nothing while SSO is off.
const SsoSignInButton = ({ next, mode = 'signin', className = '' }) => {
  const [config, setConfig] = useState(null)
  const [redirecting, setRedirecting] = useState(false)

  useEffect(() => {
    let active = true
    getSsoConfig().then((value) => {
      if (active) {
        setConfig(value)
      }
    })
    return () => {
      active = false
    }
  }, [])

  if (!config?.enabled || (mode === 'signup' && !config.allow_signup)) {
    return null
  }

  return (
    <div className={className}>
      <button
        type="button"
        disabled={redirecting}
        onClick={() => {
          setRedirecting(true)
          startSsoLogin(next)
        }}
        className="flex h-11 w-full items-center justify-center gap-2 rounded-xl border border-[rgb(var(--theme-border-rgb))] bg-white text-sm font-semibold text-foreground transition hover:border-primary/60 hover:bg-[rgb(var(--theme-muted-rgb)/0.5)] disabled:opacity-60"
      >
        <KeyRound className="h-4 w-4 text-primary" />
        {redirecting ? 'Redirecting…' : `Continue with ${config.label}`}
      </button>
      <div className="mt-6 flex items-center gap-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        <span className="h-px flex-1 bg-[rgb(var(--theme-border-rgb))]" />
        or
        <span className="h-px flex-1 bg-[rgb(var(--theme-border-rgb))]" />
      </div>
    </div>
  )
}

export default SsoSignInButton
