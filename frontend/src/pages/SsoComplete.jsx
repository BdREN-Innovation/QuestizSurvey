import { useEffect } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { LoaderCircle } from 'lucide-react'

import { useAuth } from '../contexts/AuthContext'
import { getSafeRedirect } from '@/utils/redirects'

// Landing page after a successful single sign-on. The backend has already set the refresh
// cookie; AuthProvider's start-up refresh signs the user in, so this page only waits for it.
const SsoComplete = () => {
  const { isAuthenticated, loading } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const next = getSafeRedirect(searchParams.get('next'))

  useEffect(() => {
    if (!loading && isAuthenticated) {
      navigate(next, { replace: true })
    }
  }, [loading, isAuthenticated, navigate, next])

  if (!loading && !isAuthenticated) {
    return <Navigate to="/login?sso_error=session" replace />
  }

  return (
    <div className="theme-app-gradient flex h-[calc(100vh-4rem)] items-center justify-center">
      <div className="theme-panel flex items-center gap-3 rounded-2xl px-5 py-4">
        <LoaderCircle className="h-5 w-5 animate-spin text-primary" />
        <span className="text-sm font-medium text-muted-foreground">Signing you in…</span>
      </div>
    </div>
  )
}

export default SsoComplete
