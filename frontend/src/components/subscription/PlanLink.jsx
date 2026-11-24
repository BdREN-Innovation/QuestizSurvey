import { Link } from 'react-router-dom'

import { useBillingConfig } from '@/services/billing'

// Where "upgrade / manage plan" goes: the Pricing page, or bdren.ai when it manages plans.
function PlanLink({ children, ...props }) {
  const { managedExternally, manageUrl } = useBillingConfig()

  if (managedExternally && manageUrl) {
    return (
      <a href={manageUrl} target="_blank" rel="noopener noreferrer" {...props}>
        {children}
      </a>
    )
  }
  return (
    <Link to="/pricing" {...props}>
      {children}
    </Link>
  )
}

export default PlanLink
