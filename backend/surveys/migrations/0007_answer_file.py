from django.db import migrations, models

import surveys.uploads


class Migration(migrations.Migration):
    dependencies = [("surveys", "0006_hash_public_link_passwords")]

    operations = [
        migrations.AddField(
            model_name="answer",
            name="file",
            field=models.FileField(
                blank=True,
                max_length=500,
                storage=surveys.uploads.ResponseFileStorage(),
                upload_to=surveys.uploads.response_file_path,
            ),
        ),
        migrations.AddField(
            model_name="answer",
            name="file_name",
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
