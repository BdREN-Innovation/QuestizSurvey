export const MAX_UPLOAD_MB = 20

export function isUploadFile(value) {
  return typeof File !== 'undefined' && value instanceof File
}

export function getFileRules(question) {
  const allowedTypes = question?.settings?.allowed_types ?? ['pdf', 'png', 'jpg']
  const configuredMax = Number(question?.settings?.max_file_size_mb ?? 10)
  return {
    allowedTypes,
    maxSizeMb: Math.min(Number.isFinite(configuredMax) ? configuredMax : 10, MAX_UPLOAD_MB),
    extensions: [...new Set(allowedTypes.flatMap((type) => {
      if (type === 'jpg') return ['jpg', 'jpeg']
      if (type === 'doc') return ['doc', 'docx']
      return [type]
    }))],
  }
}

export function validateUploadFile(question, value) {
  if (!isUploadFile(value)) return ''
  const { extensions, maxSizeMb } = getFileRules(question)
  const extension = value.name.split('.').pop().toLowerCase()
  if (!extensions.includes(extension)) return 'This file type is not allowed for this question.'
  if (!value.size || value.size > maxSizeMb * 1024 * 1024) {
    return `Choose a non-empty file no larger than ${maxSizeMb} MB.`
  }
  return ''
}

export function getUploadedFileName(value) {
  if (value?.name) return value.name
  if (typeof value === 'string' && value) {
    try {
      return decodeURIComponent(value.split('?')[0].split('/').pop()) || 'Saved file'
    } catch {
      return 'Saved file'
    }
  }
  return ''
}

export function buildPublicSubmissionBody(payload, files = {}) {
  const entries = Object.entries(files).filter(([, value]) => isUploadFile(value))
  if (!entries.length) return payload
  const body = new FormData()
  body.append('payload', JSON.stringify(payload))
  entries.forEach(([questionId, file]) => body.append(`file_${questionId}`, file))
  return body
}
