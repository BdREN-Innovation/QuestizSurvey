# Deploying response file uploads

This release adds migration `surveys.0007_answer_file`. Deploy the backend and frontend together.

## Ubuntu / systemd production

Run from the existing checkout as the application owner:

```bash
cd /srv/questizsurvey/app
git pull --ff-only origin main
cd backend
source venv/bin/activate
mkdir -p private_uploads
chmod 700 private_uploads
python manage.py migrate --noinput
cd ../frontend
npm ci
npm run build
sudo systemctl restart questiz-gunicorn questiz-celery
```

The Gunicorn service user must own and be able to write to `backend/private_uploads`.
By default, files are stored there, outside the public `media` directory. To store
them elsewhere, set `PRIVATE_UPLOAD_ROOT` in the backend environment to a private,
absolute directory writable by the service user. Do not configure an Nginx alias
for this directory. Back it up alongside the database and retain it across deployments.

Downloads use the existing `/api/` proxy, so no new Nginx route is needed. The
existing Ubuntu Nginx template permits 25 MB requests. If production differs,
set `client_max_body_size 25M;`, run `sudo nginx -t`, and reload Nginx.
Uploads are capped at 20 MB total per save and each question's configured limit.

## Verify

1. Submit an active survey with a real PDF or allowed image/document.
2. In Analyze → Responses, download the file and verify its name and contents.
3. Save and resume a response; the saved filename should remain visible.
4. A different account or an anonymous request must not download the file.
5. Replace/remove the file and delete a test response; old files should be removed.

Automated checks:

```bash
cd backend
python manage.py test surveys.tests.test_file_uploads
cd ../frontend
npm run test:uploads
npm run build
```

## Existing responses

Previously selected files were never transmitted by the broken upload flow. No
migration can recover their contents. Empty historical answers now show “No file
available”; respondents must provide those files again. Existing non-empty
external file URLs remain supported.
