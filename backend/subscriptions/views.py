import json
from functools import wraps

from django.conf import settings
from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from rest_framework import generics, status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from questizsurvey.audit import log_audit_event

from . import bdren
from .models import Plan
from .serializers import PlanSerializer, UserSubscriptionSerializer
from .services import LicenseService


class PlanListView(generics.ListAPIView):
    permission_classes = [AllowAny]
    serializer_class = PlanSerializer
    pagination_class = None

    def get_queryset(self):
        return Plan.objects.filter(is_active=True).order_by("tier")


class CurrentSubscriptionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        subscription = LicenseService.get_user_subscription(request.user)
        serializer = UserSubscriptionSerializer(subscription)
        return Response(serializer.data)


class SubscriptionUsageView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(LicenseService.get_usage_snapshot(request.user))


class SubscriptionCancelView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        with transaction.atomic():
            subscription = LicenseService.get_user_subscription(
                request.user, for_update=True
            )

            if not LicenseService.is_subscription_paid_and_active(subscription):
                return Response(
                    {"detail": "There is no active paid subscription to cancel."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if subscription.payment_provider == subscription.PaymentProvider.STRIPE:
                return Response(
                    {
                        "detail": "Stripe-managed subscriptions must be canceled from the billing portal.",
                        "code": "stripe_customer_portal_required",
                    },
                    status=status.HTTP_409_CONFLICT,
                )

            if subscription.payment_provider != subscription.PaymentProvider.BKASH:
                return Response(
                    {"detail": "This subscription cannot be canceled from here."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            LicenseService.cancel_bkash_subscription_at_period_end(subscription)
            serializer = UserSubscriptionSerializer(subscription)
        return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([AllowAny])
@authentication_classes([])
def billing_config_view(request):
    """Public: whether plans are sold here or managed on bdren.ai."""
    return Response(bdren.public_config())


def local_billing_only(view):
    """Refuse new checkouts while bdren.ai manages plans. Webhooks, callbacks, status checks, the
    Stripe customer portal and bKash cancellation stay open so older payments can finish or stop."""

    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if bdren.is_bdren_mode():
            return JsonResponse(bdren.gone_payload(), status=410)
        return view(request, *args, **kwargs)

    return wrapped


@csrf_exempt
@require_POST
def bdren_webhook_view(request):
    """Signed events from bdren.ai (docs/ALLOWANCE_AND_WEBHOOKS.md in bdren.ai). Each one only
    means "refresh the allowance", so it drops the cached answer and returns 200."""
    if not bdren.is_bdren_mode() or not settings.BDREN_WEBHOOK_SECRET:
        return JsonResponse({"detail": "Not found."}, status=404)

    body = request.body
    if not bdren.verify_signature(
        request.headers.get("X-BdREN-Signature", ""),
        request.headers.get("X-BdREN-Timestamp", ""),
        body,
    ):
        log_audit_event(
            "bdren_webhook", outcome="failure", level="warning", request=request,
            reason="bad_signature",
        )
        return JsonResponse({"detail": "Invalid signature."}, status=400)

    try:
        event = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return JsonResponse({"detail": "Invalid JSON."}, status=400)
    if not isinstance(event, dict):
        return JsonResponse({"detail": "Invalid event."}, status=400)

    result = bdren.handle_event(event)
    log_audit_event(
        "bdren_webhook",
        request=request,
        event_id=str(event.get("id") or ""),
        event_type=str(event.get("type") or ""),
        reason=str(event.get("reason") or ""),
        result=result,
    )
    return JsonResponse({"ok": True, "result": result})
