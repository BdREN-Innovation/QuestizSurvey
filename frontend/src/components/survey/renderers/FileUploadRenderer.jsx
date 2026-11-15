import { getFileRules, getUploadedFileName, validateUploadFile } from '@/utils/fileUploads'

export default function FileUploadRenderer({ question, value, onChange, disabled = false }) {
  const { allowedTypes, extensions, maxSizeMb } = getFileRules(question)
  const fileName = getUploadedFileName(value)
  const error = validateUploadFile(question, value)
  return (
    <div className="space-y-2">
      <label className="survey-theme-filedrop flex min-h-[160px] cursor-pointer flex-col items-center justify-center px-6 text-center focus-within:ring-2 focus-within:ring-primary focus-within:ring-offset-2">
        <span className="max-w-full break-all text-sm font-semibold text-foreground">
          {fileName || 'Choose a file'}
        </span>
        <span className="survey-theme-muted mt-1 text-sm">
          {allowedTypes.length ? allowedTypes.join(', ').toUpperCase() : 'No file types enabled'} · Up to {maxSizeMb} MB
        </span>
        {fileName ? <span className="survey-theme-muted mt-1 text-xs">Choose another file to replace it</span> : null}
        <input
          type="file"
          disabled={disabled}
          accept={extensions.map((type) => `.${type}`).join(',')}
          aria-label={fileName ? `Replace ${fileName}` : 'Choose a file'}
          className="sr-only"
          onChange={(event) => {
            const file = event.target.files?.[0]
            if (file) onChange(file)
            event.target.value = ''
          }}
        />
      </label>
      {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
      {fileName ? (
        <button type="button" disabled={disabled} onClick={() => onChange(null)} className="text-sm text-muted-foreground underline underline-offset-4">
          Remove file
        </button>
      ) : null}
    </div>
  )
}
