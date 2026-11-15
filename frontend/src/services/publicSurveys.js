import api from '@/services/api'
import { buildPublicSubmissionBody } from '@/utils/fileUploads'

export async function fetchPublicSurvey(
  slug,
  { resumeToken = '', invitationToken = '', accessKey = '' } = {}
) {
  const payload = {}

  if (resumeToken) {
    payload.resume_token = resumeToken
  }

  if (invitationToken) {
    payload.invitation_token = invitationToken
  }

  if (accessKey) {
    payload.access_key = accessKey
  }

  const response = await api.post(`/public/surveys/${slug}/load/`, payload, {
    preserveAuthError: true,
  })
  return response.data
}

export async function submitPublicSurvey(slug, payload, files = {}) {
  const body = buildPublicSubmissionBody(payload, files)
  const response = await api.post(`/public/surveys/${slug}/`, body, {
    preserveAuthError: true,
    ...(body instanceof FormData ? { headers: { 'Content-Type': 'multipart/form-data' } } : {}),
  })
  return response.data
}

export async function updatePublicSurvey(slug, payload, files = {}) {
  const body = buildPublicSubmissionBody(payload, files)
  const response = await api.put(`/public/surveys/${slug}/`, body, {
    preserveAuthError: true,
    ...(body instanceof FormData ? { headers: { 'Content-Type': 'multipart/form-data' } } : {}),
  })
  return response.data
}
