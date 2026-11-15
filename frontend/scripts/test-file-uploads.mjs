import assert from 'node:assert/strict'
import { File } from 'node:buffer'
import { fileURLToPath } from 'node:url'
import { after, test } from 'node:test'
import { createServer } from 'vite'

import { buildPublicSubmissionBody, validateUploadFile } from '../src/utils/fileUploads.js'

globalThis.File = File
const server = await createServer({
  configFile: false,
  resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
  server: { middlewareMode: true, hmr: false },
  optimizeDeps: { noDiscovery: true, include: [] },
})
after(() => server.close())
const { collectPublicAnswerFiles, restorePublicAnswers, serializePublicAnswers, validateSurveyPage } =
  await server.ssrLoadModule('/src/utils/publicSurvey.js')
const question = {
  id: 'file-question', question_type: 'file_upload', required: true,
  settings: { allowed_types: ['pdf'], max_file_size_mb: 1 },
}
const page = { id: 'page', questions: [question] }
const survey = { pages: [page] }

test('selected file is sent as multipart bytes alongside intact nested JSON', async () => {
  const file = new File(['%PDF-1.4\nexample'], 'example.pdf', { type: 'application/pdf' })
  const answers = { [question.id]: { value: file, comment_text: '', other_text: '' } }
  assert.deepEqual(validateSurveyPage(page, answers), {})
  const payload = { status: 'completed', answers: serializePublicAnswers(survey, answers) }
  const body = buildPublicSubmissionBody(payload, collectPublicAnswerFiles(survey, answers))
  assert.ok(body instanceof FormData)
  assert.deepEqual(JSON.parse(body.get('payload')), payload)
  assert.equal(body.get(`file_${question.id}`).name, 'example.pdf')
  assert.equal(await body.get(`file_${question.id}`).text(), '%PDF-1.4\nexample')
  assert.equal(payload.answers[0].remove_file, false)
})

test('save and resume retain the filename without reuploading or clearing the saved file', () => {
  const answers = restorePublicAnswers(survey, {
    answers: [{ question_id: question.id, file_name: 'saved.pdf', file_url: '' }],
  })
  assert.equal(answers[question.id].value.name, 'saved.pdf')
  assert.deepEqual(validateSurveyPage(page, answers), {})
  assert.deepEqual(collectPublicAnswerFiles(survey, answers), {})
  assert.equal(serializePublicAnswers(survey, answers)[0].remove_file, false)
})

test('removing a file explicitly clears it; ordinary answers remain JSON', () => {
  const answers = { [question.id]: null }
  const payload = { answers: serializePublicAnswers(survey, answers) }
  assert.equal(payload.answers[0].remove_file, true)
  assert.equal(buildPublicSubmissionBody(payload), payload)
  assert.equal(validateSurveyPage(page, answers)[question.id], 'Add a file before continuing.')
})

test('type and size rules apply to optional as well as required file questions', () => {
  const wrongType = new File(['html'], 'example.html')
  const tooLarge = new File([new Uint8Array(1024 * 1024 + 1)], 'large.pdf')
  assert.match(validateUploadFile(question, wrongType), /file type/)
  assert.match(validateUploadFile(question, tooLarge), /1 MB/)
  const optionalPage = { ...page, questions: [{ ...question, required: false }] }
  assert.match(validateSurveyPage(optionalPage, { [question.id]: wrongType })[question.id], /file type/)
})

test('public API services preserve multipart bodies for both create and update', async () => {
  const { default: api } = await server.ssrLoadModule('/src/services/api.js')
  const { submitPublicSurvey, updatePublicSurvey } = await server.ssrLoadModule('/src/services/publicSurveys.js')
  const payload = { status: 'in_progress', answers: [{ question: question.id }] }
  const file = new File(['%PDF-1.4'], 'example.pdf')
  const methods = []
  api.defaults.adapter = async (config) => {
    assert.ok(config.data instanceof FormData)
    assert.match(config.headers['Content-Type'], /multipart\/form-data/)
    assert.equal(config.data.get(`file_${question.id}`).name, file.name)
    const json = JSON.parse(config.data.get('payload'))
    assert.deepEqual(json.answers, payload.answers)
    if (config.method === 'put') assert.equal(json.resume_token, 'resume-token')
    methods.push(config.method)
    return { data: { saved: true }, status: 200, headers: {}, config }
  }
  await submitPublicSurvey('example', payload, { [question.id]: file })
  await updatePublicSurvey('example', { ...payload, resume_token: 'resume-token' }, { [question.id]: file })
  assert.deepEqual(methods, ['post', 'put'])
})

test('downloads use the authenticated API client and create a browser download', async () => {
  const { default: api } = await server.ssrLoadModule('/src/services/api.js')
  const { downloadResponseFile } = await server.ssrLoadModule('/src/services/analytics.js')
  const { setAccessToken } = await server.ssrLoadModule('/src/services/api.js')
  const events = []
  const blob = new Blob(['file contents'])
  api.defaults.adapter = async (config) => {
    assert.equal(config.url, '/surveys/survey/responses/response/files/answer/')
    assert.equal(config.responseType, 'blob')
    assert.equal(config.headers.Authorization, 'Bearer test-access-token')
    return { data: blob, status: 200, headers: {}, config }
  }
  globalThis.document = {
    body: { appendChild: (link) => events.push(['append', link]) },
    createElement: () => ({ click() { events.push(['click', this.download]) }, remove() {} }),
  }
  globalThis.window = { setTimeout: (callback) => callback() }
  setAccessToken('test-access-token')
  await downloadResponseFile('survey', 'response', 'answer', 'evidence.pdf')
  assert.equal(events[0][1].download, 'evidence.pdf')
  assert.deepEqual(events[1], ['click', 'evidence.pdf'])
})
