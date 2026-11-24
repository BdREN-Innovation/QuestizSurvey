import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { CheckCircle2, KeyRound, LoaderCircle } from 'lucide-react'

import { useAuth } from '@/contexts/AuthContext'
import { useToast } from '@/hooks/useToast'
import { requestPasswordReset } from '@/services/auth'
import { getSsoConfig, ssoErrorMessage, startSsoLink, unlinkSso } from '@/services/sso'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

// Profile card for single sign-on: link, unlink, and set a password for SSO-only accounts.
// Renders nothing while SSO is off.
const SsoLinkCard = () => {
  const { user, refreshUser } = useAuth()
  const { toast } = useToast()
  const [searchParams, setSearchParams] = useSearchParams()
  const [config, setConfig] = useState(null)
  const [busy, setBusy] = useState('')
  const handledResult = useRef(false)

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

  // Result of a linking round-trip through the provider.
  useEffect(() => {
    const linked = searchParams.get('sso_linked')
    const errorCode = searchParams.get('sso_error')
    if ((!linked && !errorCode) || handledResult.current) {
      return
    }
    handledResult.current = true
    if (linked) {
      toast({ title: 'Account linked', variant: 'success', duration: 4200 })
      refreshUser()
    } else {
      toast({
        title: 'Could not link account',
        description: ssoErrorMessage(errorCode),
        variant: 'error',
        duration: 6000,
      })
    }
    const next = new URLSearchParams(searchParams)
    next.delete('sso_linked')
    next.delete('sso_error')
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams, toast, refreshUser])

  if (!config?.enabled || !user) {
    return null
  }

  const label = config.label
  const linked = Boolean(user.sso_linked)
  const hasPassword = user.has_usable_password !== false

  const handleLink = async () => {
    setBusy('link')
    try {
      await startSsoLink()
    } catch (err) {
      setBusy('')
      toast({
        title: 'Could not start linking',
        description: err.response?.data?.detail || 'Please try again.',
        variant: 'error',
      })
    }
  }

  const handleUnlink = async () => {
    setBusy('unlink')
    try {
      await unlinkSso()
      await refreshUser()
      toast({ title: `Unlinked from ${label}`, variant: 'success' })
    } catch (err) {
      toast({
        title: 'Could not unlink',
        description: err.response?.data?.detail || 'Please try again.',
        variant: 'error',
      })
    }
    setBusy('')
  }

  const handleSetPassword = async () => {
    setBusy('password')
    try {
      await requestPasswordReset(user.email)
      toast({
        title: 'Check your email',
        description: 'We sent a link to set a password for your account.',
        variant: 'success',
        duration: 5000,
      })
    } catch (err) {
      toast({
        title: 'Could not send the email',
        description: err.response?.data?.detail || 'Please try again later.',
        variant: 'error',
      })
    }
    setBusy('')
  }

  return (
    <Card className="theme-panel border-0">
      <CardHeader className="pb-4">
        <CardTitle>Sign-in methods</CardTitle>
        <CardDescription>
          Sign in with your {label} account, your password, or both.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-col gap-3 rounded-2xl border border-[rgb(var(--theme-border-rgb)/0.9)] px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <span className="theme-icon-secondary inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full">
              {linked ? <CheckCircle2 className="h-4 w-4" /> : <KeyRound className="h-4 w-4" />}
            </span>
            <div>
              <p className="text-sm font-semibold text-foreground">{label}</p>
              <p className="text-sm text-muted-foreground">
                {linked
                  ? `Linked. You can sign in with ${label}.`
                  : `Not linked. Link it to sign in with your ${label} account.`}
              </p>
            </div>
          </div>
          {linked ? (
            <Button
              type="button"
              variant="outline"
              className="rounded-full"
              onClick={handleUnlink}
              disabled={Boolean(busy) || !hasPassword}
              title={hasPassword ? undefined : 'Set a password first'}
            >
              {busy === 'unlink' ? <LoaderCircle className="mr-2 h-4 w-4 animate-spin" /> : null}
              Unlink
            </Button>
          ) : (
            <Button
              type="button"
              className="rounded-full"
              onClick={handleLink}
              disabled={Boolean(busy)}
            >
              {busy === 'link' ? <LoaderCircle className="mr-2 h-4 w-4 animate-spin" /> : null}
              Link {label} account
            </Button>
          )}
        </div>

        {!hasPassword ? (
          <div className="flex flex-col gap-3 rounded-2xl border border-dashed border-[rgb(var(--theme-border-rgb)/0.9)] px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm text-muted-foreground">
              Your account has no password yet. Set one so you can also sign in without {label}.
            </p>
            <Button
              type="button"
              variant="secondary"
              className="rounded-full"
              onClick={handleSetPassword}
              disabled={Boolean(busy)}
            >
              {busy === 'password' ? <LoaderCircle className="mr-2 h-4 w-4 animate-spin" /> : null}
              Set a password
            </Button>
          </div>
        ) : null}
      </CardContent>
    </Card>
  )
}

export default SsoLinkCard
