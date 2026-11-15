"""Private response-file storage and multipart submission parsing."""

import json
import logging
import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.db import transaction
from rest_framework.exceptions import ParseError, ValidationError
from rest_framework.parsers import DataAndFiles, MultiPartParser

logger = logging.getLogger(__name__)
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
SUPPORTED_TYPES = {"pdf", "png", "jpg", "jpeg", "doc", "docx"}


class ResponseFileStorage(FileSystemStorage):
    @property
    def base_location(self):
        return settings.PRIVATE_UPLOAD_ROOT

    @property
    def location(self):
        return os.path.abspath(self.base_location)

    def url(self, name):
        raise NotImplementedError("Response files require an authenticated download.")


def response_file_path(instance, filename):
    extension = Path(filename).suffix.lower()
    return f"{instance.response.survey_id}/{instance.response_id}/{uuid.uuid4().hex}{extension}"


def response_file_name(filename):
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    return (
        "".join(character for character in name if character.isprintable()).strip()
        or "upload"
    )


def delete_response_file(storage, name):
    if name:
        try:
            storage.delete(name)
        except OSError:
            logger.exception("Could not delete response file %s", name)


def delete_response_file_after_commit(file):
    if file:
        storage, name = file.storage, file.name
        transaction.on_commit(lambda: delete_response_file(storage, name))


@contextmanager
def cleanup_failed_uploads(context):
    context["saved_uploads"] = []
    try:
        yield
    except Exception:
        for storage, name in context["saved_uploads"]:
            delete_response_file(storage, name)
        raise


def validate_response_file(question, upload):
    if question.question_type != "file_upload":
        raise ValidationError("Files can only be attached to file-upload questions.")
    extension = Path(upload.name).suffix.lower().lstrip(".")
    allowed = set(question.settings.get("allowed_types", ["pdf", "png", "jpg"]) or [])
    if "jpg" in allowed:
        allowed.add("jpeg")
    if "doc" in allowed:
        allowed.add("docx")
    if extension not in allowed.intersection(SUPPORTED_TYPES):
        raise ValidationError("This file type is not allowed for this question.")
    try:
        max_bytes = min(
            float(question.settings.get("max_file_size_mb", 10)) * 1024 * 1024,
            MAX_UPLOAD_BYTES,
        )
    except (TypeError, ValueError):
        max_bytes = 10 * 1024 * 1024
    if not 0 < upload.size <= max_bytes:
        raise ValidationError(
            f"Choose a non-empty file no larger than {max_bytes / 1024 / 1024:g} MB."
        )

    header = upload.read(8)
    upload.seek(0)
    signatures = {
        "pdf": b"%PDF-",
        "png": b"\x89PNG\r\n\x1a\n",
        "jpg": b"\xff\xd8\xff",
        "jpeg": b"\xff\xd8\xff",
        "doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    }
    valid = header.startswith(signatures.get(extension, b"PK\x03\x04"))
    if extension == "docx" and valid:
        try:
            with ZipFile(upload) as archive:
                valid = {"[Content_Types].xml", "word/document.xml"}.issubset(
                    archive.namelist()
                )
        except BadZipFile:
            valid = False
        finally:
            upload.seek(0)
    if not valid:
        raise ValidationError("The file contents do not match its file type.")


class SurveySubmissionMultipartParser(MultiPartParser):
    """Keep nested JSON answers intact while attaching files by question ID."""

    def parse(self, stream, media_type=None, parser_context=None):
        parsed = super().parse(stream, media_type, parser_context)
        try:
            return self.bind_files(parsed)
        except Exception:
            for files in parsed.files.lists():
                for file in files[1]:
                    file.close()
            raise

    def bind_files(self, parsed):
        try:
            payload = json.loads(parsed.data["payload"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ParseError("A valid JSON payload is required.") from exc
        if not isinstance(payload, dict) or not isinstance(
            payload.get("answers", []), list
        ):
            raise ParseError("Invalid survey submission payload.")

        used = set()
        for answer in payload.get("answers", []):
            if not isinstance(answer, dict):
                raise ParseError("Invalid answer payload.")
            key = f"file_{answer.get('question')}"
            if key in parsed.files:
                if key in used or len(parsed.files.getlist(key)) != 1:
                    raise ParseError("Only one file per question is allowed.")
                answer["file"] = parsed.files[key]
                used.add(key)
        if used != set(parsed.files):
            raise ParseError("Each uploaded file must belong to a submitted answer.")
        return DataAndFiles(payload, parsed.files)
