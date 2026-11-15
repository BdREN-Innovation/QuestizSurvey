import json
import logging
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zipfile import ZipFile

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from PIL import Image

from surveys.models import Answer, Page, Question, Survey, SurveyResponse


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
)
class ResponseFileTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.owner = User.objects.create_user(
            username="file-owner", email="owner@example.com"
        )
        cls.other = User.objects.create_user(
            username="file-other", email="other@example.com"
        )
        cls.survey = Survey.objects.create(
            user=cls.owner, title="Attachments", status=Survey.Status.ACTIVE
        )
        cls.page = Page.objects.create(survey=cls.survey, title="Files", order=1)
        cls.question = Question.objects.create(
            page=cls.page,
            question_type=Question.QuestionType.FILE_UPLOAD,
            text="Your document",
            required=True,
            order=1,
            settings={"allowed_types": ["pdf"], "max_file_size_mb": 1},
        )

    def setUp(self):
        cache.clear()
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        override = override_settings(PRIVATE_UPLOAD_ROOT=self.root)
        override.enable()
        self.addCleanup(override.disable)
        self.public = APIClient()
        self.owner_client = APIClient()
        self.owner_client.force_authenticate(self.owner)
        self.other_client = APIClient()
        self.other_client.force_authenticate(self.other)
        self.url = f"/api/public/surveys/{self.survey.slug}/"

    def upload(
        self,
        *,
        content=b"%PDF-1.4\nfile contents\n%%EOF",
        name="evidence.pdf",
        question=None,
        payload=None,
    ):
        question = question or self.question
        payload = payload or {
            "status": "completed",
            "answers": [{"question": str(question.id)}],
        }
        return self.public.post(
            self.url,
            {
                "payload": json.dumps(payload),
                f"file_{question.id}": SimpleUploadedFile(name, content),
            },
            format="multipart",
        )

    def download_url(self, answer):
        return f"/api/surveys/{self.survey.id}/responses/{answer.response_id}/files/{answer.id}/"

    def test_upload_stores_bytes_privately_and_owner_can_download(self):
        result = self.upload(name="রিপোর্ট.pdf")
        self.assertEqual(result.status_code, 201, result.data)
        answer = Answer.objects.get(question=self.question)
        self.assertTrue(answer.file.storage.exists(answer.file.name))
        self.assertTrue(answer.file.path.startswith(str(self.root)))
        self.assertEqual(answer.file_name, "রিপোর্ট.pdf")
        self.assertNotIn("/media/", answer.file_url)
        self.assertEqual(result.data["answers"][0]["file_url"], "")
        self.assertNotIn(answer.file.name, result.content.decode())
        detail = self.owner_client.get(
            f"/api/surveys/{self.survey.id}/responses/{answer.response_id}/"
        )
        self.assertEqual(detail.data["answers"][0]["file_url"], answer.file_url)
        analytics = self.owner_client.get(
            f"/api/surveys/{self.survey.id}/analytics/questions/{self.question.id}/?include_insights=false"
        )
        self.assertEqual(analytics.status_code, 200)
        self.assertEqual(analytics.data["files"][0]["file_type"], "pdf")

        download = self.owner_client.get(self.download_url(answer))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(
            b"".join(download.streaming_content), b"%PDF-1.4\nfile contents\n%%EOF"
        )
        self.assertIn("attachment;", download["Content-Disposition"])
        self.assertIn("filename*=utf-8", download["Content-Disposition"])
        self.assertEqual(download["Cache-Control"], "private, no-store")
        self.assertEqual(download["X-Content-Type-Options"], "nosniff")
        download.close()

    def test_anonymous_and_other_user_cannot_download(self):
        self.upload()
        answer = Answer.objects.get(question=self.question)
        self.assertEqual(self.public.get(self.download_url(answer)).status_code, 401)
        self.assertEqual(
            self.other_client.get(self.download_url(answer)).status_code, 404
        )

    def test_download_cannot_mix_response_and_answer_ids(self):
        self.upload()
        self.upload()
        first, second = Answer.objects.all()[:2]
        url = self.download_url(first).replace(str(first.id), str(second.id))
        self.assertEqual(self.owner_client.get(url).status_code, 404)

    def test_saved_file_survives_json_update_and_resume(self):
        result = self.upload(
            payload={
                "status": "in_progress",
                "answers": [{"question": str(self.question.id)}],
            }
        )
        token = result.data["resume_token"]
        answer = Answer.objects.get(question=self.question)
        original_name = answer.file.name
        loaded = self.public.post(
            f"{self.url}load/", {"resume_token": token}, format="json"
        )
        self.assertEqual(
            loaded.data["response"]["answers"][0]["file_name"], "evidence.pdf"
        )
        self.assertEqual(loaded.data["response"]["answers"][0]["file_url"], "")
        updated = self.public.put(
            self.url,
            {
                "resume_token": token,
                "status": "completed",
                "answers": [{"question": str(self.question.id), "file_url": ""}],
            },
            format="json",
        )
        self.assertEqual(updated.status_code, 200, updated.data)
        answer.refresh_from_db()
        self.assertEqual(answer.file.name, original_name)
        self.assertTrue(answer.file.storage.exists(original_name))

    def test_replace_and_remove_file_clean_up_storage(self):
        created = self.upload(
            payload={
                "status": "in_progress",
                "answers": [{"question": str(self.question.id)}],
            }
        )
        token = created.data["resume_token"]
        answer = Answer.objects.get(question=self.question)
        old_path = Path(answer.file.path)
        payload = {
            "resume_token": token,
            "answers": [{"question": str(self.question.id)}],
        }
        with self.captureOnCommitCallbacks(execute=True):
            updated = self.public.put(
                self.url,
                {
                    "payload": json.dumps(payload),
                    f"file_{self.question.id}": SimpleUploadedFile(
                        "replacement.pdf", b"%PDF-1.7\nnew file"
                    ),
                },
                format="multipart",
            )
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertFalse(old_path.exists())
        answer.refresh_from_db()
        new_path = Path(answer.file.path)
        with self.captureOnCommitCallbacks(execute=True):
            removed = self.public.put(
                self.url,
                {
                    "resume_token": token,
                    "answers": [
                        {"question": str(self.question.id), "remove_file": True}
                    ],
                },
                format="json",
            )
        self.assertEqual(removed.status_code, 200, removed.data)
        self.assertFalse(new_path.exists())
        answer.refresh_from_db()
        self.assertFalse(answer.file)
        self.assertEqual(answer.file_url, "")

    def test_deleting_response_also_deletes_file(self):
        self.upload()
        answer = Answer.objects.get(question=self.question)
        path = Path(answer.file.path)
        with self.captureOnCommitCallbacks(execute=True):
            result = self.owner_client.delete(
                f"/api/surveys/{self.survey.id}/responses/{answer.response_id}/"
            )
        self.assertEqual(result.status_code, 204)
        self.assertFalse(path.exists())

    def test_missing_stored_file_returns_404(self):
        self.upload()
        answer = Answer.objects.get(question=self.question)
        answer.file.storage.delete(answer.file.name)
        self.assertEqual(
            self.owner_client.get(self.download_url(answer)).status_code, 404
        )

    def test_legacy_empty_file_has_no_download(self):
        response = SurveyResponse.objects.create(survey=self.survey)
        answer = Answer.objects.create(response=response, question=self.question)
        self.assertEqual(
            self.owner_client.get(self.download_url(answer)).status_code, 404
        )

    def test_rejects_disallowed_type_spoofed_contents_and_oversized_file(self):
        for name, content in [
            ("script.html", b"<html>unsafe</html>"),
            ("fake.pdf", b"<html>not a PDF</html>"),
            ("large.pdf", b"%PDF-" + b"x" * 1024 * 1024),
            ("empty.pdf", b""),
        ]:
            with self.subTest(name=name):
                self.assertEqual(
                    self.upload(name=name, content=content).status_code, 400
                )
        self.assertFalse(SurveyResponse.objects.exists())
        self.assertEqual(list(self.root.rglob("*.pdf")), [])

    def test_rejects_upload_for_another_survey_or_non_file_question(self):
        other_survey = Survey.objects.create(
            user=self.owner, title="Other", status=Survey.Status.ACTIVE
        )
        other_page = Page.objects.create(survey=other_survey, order=1)
        foreign_question = Question.objects.create(
            page=other_page, question_type="file_upload", text="Foreign", order=1
        )
        text_question = Question.objects.create(
            page=self.page, question_type="short_text", text="Text", order=2
        )
        for question in [foreign_question, text_question]:
            self.assertEqual(self.upload(question=question).status_code, 400)
        self.assertFalse(SurveyResponse.objects.exists())

    def test_required_file_cannot_be_faked_with_url(self):
        result = self.public.post(
            self.url,
            {
                "status": "completed",
                "answers": [
                    {
                        "question": str(self.question.id),
                        "file_url": "https://example.com/fake.pdf",
                    }
                ],
            },
            format="json",
        )
        self.assertEqual(result.status_code, 400)
        self.assertFalse(SurveyResponse.objects.exists())

    def test_upload_accepts_supported_images_and_word_documents(self):
        self.question.settings = {"allowed_types": ["png", "jpg", "doc"]}
        self.question.save(update_fields=["settings"])
        for format, extension in [("PNG", "png"), ("JPEG", "jpeg")]:
            content = BytesIO()
            Image.new("RGB", (2, 2)).save(content, format=format)
            self.assertEqual(
                self.upload(
                    name=f"image.{extension}", content=content.getvalue()
                ).status_code,
                201,
            )
        content = BytesIO()
        with ZipFile(content, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types />")
            archive.writestr("word/document.xml", "<document />")
        self.assertEqual(
            self.upload(name="document.docx", content=content.getvalue()).status_code,
            201,
        )
        self.assertEqual(
            self.upload(
                name="document.docx", content=b"PK\x03\x04not a docx"
            ).status_code,
            400,
        )

    def test_multiple_uploads_and_aggregate_limit(self):
        self.question.settings = {"allowed_types": ["pdf"], "max_file_size_mb": 20}
        self.question.save(update_fields=["settings"])
        second = Question.objects.create(
            page=self.page,
            question_type="file_upload",
            text="Second document",
            order=2,
            settings=self.question.settings,
        )
        payload = {
            "answers": [
                {"question": str(self.question.id)},
                {"question": str(second.id)},
            ]
        }
        data = {"payload": json.dumps(payload)}
        for question in [self.question, second]:
            data[f"file_{question.id}"] = SimpleUploadedFile(
                "file.pdf", b"%PDF-1.4\nexample"
            )
        result = self.public.post(self.url, data, format="multipart")
        self.assertEqual(result.status_code, 201, result.data)
        self.assertEqual(Answer.objects.exclude(file="").count(), 2)
        data = {"payload": json.dumps(payload)}
        for question in [self.question, second]:
            data[f"file_{question.id}"] = SimpleUploadedFile(
                "large.pdf", b"%PDF-" + b"x" * (11 * 1024 * 1024)
            )
        self.assertEqual(
            self.public.post(self.url, data, format="multipart").status_code, 400
        )
        self.assertEqual(SurveyResponse.objects.count(), 1)

    def test_login_requirement_applies_to_upload(self):
        self.survey.settings = {"require_login": True}
        self.survey.save(update_fields=["settings"])
        self.assertEqual(self.upload().status_code, 401)
        self.assertFalse(SurveyResponse.objects.exists())

    def test_skipped_file_question_does_not_block_completion(self):
        final_page = Page.objects.create(survey=self.survey, title="Finish", order=2)
        Page.objects.create(
            survey=self.survey,
            title="Intro",
            order=0,
            skip_logic={"action": "skip_to_page", "target": str(final_page.id)},
        )
        result = self.public.post(
            self.url,
            {
                "status": "completed",
                "current_page": str(final_page.id),
                "answers": [
                    {
                        "question": str(self.question.id),
                        "file_url": "",
                        "remove_file": True,
                    },
                ],
            },
            format="json",
        )
        self.assertEqual(result.status_code, 201, result.data)

    def test_closed_survey_does_not_store_uploads(self):
        self.survey.status = Survey.Status.CLOSED
        self.survey.save(update_fields=["status"])
        self.assertEqual(self.upload().status_code, 410)
        self.assertEqual(list(self.root.rglob("*.pdf")), [])

    def test_rejects_malformed_multipart_and_unmatched_files(self):
        for payload in ["not json", "[]", json.dumps({"answers": []})]:
            result = self.public.post(
                self.url,
                {
                    "payload": payload,
                    f"file_{self.question.id}": SimpleUploadedFile(
                        "evidence.pdf", b"%PDF-1.4"
                    ),
                },
                format="multipart",
            )
            self.assertEqual(result.status_code, 400)

    def test_database_failure_rolls_back_and_removes_written_file(self):
        original_save = Answer.save
        with patch.object(Answer, "save", autospec=True) as save:
            # get_or_create must work; fail only after the uploaded bytes were saved.
            def fail_after_file(instance, *args, **kwargs):
                if instance.file:
                    raise RuntimeError("simulated database error")
                return original_save(instance, *args, **kwargs)

            save.side_effect = fail_after_file
            with patch.object(logging.getLogger("django.request"), "disabled", True):
                with self.assertRaisesRegex(RuntimeError, "simulated database error"):
                    self.upload()
        self.assertFalse(SurveyResponse.objects.exists())
        self.assertEqual(list(self.root.rglob("*.pdf")), [])
