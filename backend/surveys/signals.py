from django.db.models.signals import post_delete
from django.dispatch import receiver

from surveys.models import Answer
from surveys.uploads import delete_response_file_after_commit


@receiver(post_delete, sender=Answer)
def remove_answer_file(sender, instance, **kwargs):
    delete_response_file_after_commit(instance.file)
