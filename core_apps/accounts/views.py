import random
from typing import Any

from django.utils import timezone
from rest_framework import generics, status, serializers
from rest_framework.request import Request
from rest_framework.response import Response
from core_apps.common.permissions import IsAccountExecutive, IsTeller
from core_apps.common.renderers import GenericJSONRenderer
from .emails import (
    send_full_activation_email,
    send_deposit_email,
    send_withdrawal_email,
    send_transfer_email,
    send_transfer_otp_email,
)
from .models import BankAccount, Transaction
from decimal import Decimal
from .serializers import (
    AccountVerificationSerializer,
    CustomerInfoSerializer,
    DepositSerializer,
    TransactionSerializer,
    UsernameVerificationSerializer,
    SecurityQuestionSerializer,
    OTPVerificationSerializer,
)
from django.db import transaction
from loguru import logger
from django_filters.rest_framework import DjangoFilterBackend
from dateutil import parser
from django.db.models import Q
from rest_framework.filters import OrderingFilter
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework import status


class AccountVerificationView(generics.UpdateAPIView):
    queryset = BankAccount.objects.all()
    serializer_class = AccountVerificationSerializer
    renderer_classes = [GenericJSONRenderer]
    object_label = "verification"
    permission_classes = [IsAccountExecutive]

    def update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        instance = self.get_object()

        if instance.kyc_verified and instance.fully_activated:
            return Response(
                {
                    "message": "This Account has already been verified and fully activated"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        partial = kwargs.pop("partial", False)
        serializer = self.get_serializer(instance, data=request.data, partial=partial)

        if serializer.is_valid(raise_exception=True):
            kyc_submitted = serializer.validated_data.get(
                "kyc_submitted", instance.kyc_submitted
            )

            kyc_verified = serializer.validated_data.get(
                "kyc_verified", instance.kyc_verified
            )

            if kyc_verified and not kyc_submitted:
                return Response(
                    {"error": "KYC must be submitted before it can be verified."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            instance.kyc_submitted = kyc_submitted
            instance.save()

            if kyc_submitted and kyc_verified:
                instance.kyc_verified = kyc_verified
                instance.verification_date = serializer.validated_data.get(
                    "verification_date", timezone.now()
                )
                instance.verification_notes = serializer.validated_data.get(
                    "verification_notes", ""
                )
                instance.verified_by = request.user
                instance.fully_activated = True
                instance.account_status = BankAccount.AccountStatus.ACTIVE
                instance.save()

                send_full_activation_email(instance)

            return Response(
                {
                    "message": "Account Verification status updated successfully",
                    "data": self.get_serializer(instance).data,
                }
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class DepositView(generics.CreateAPIView):
    serializer_class = DepositSerializer
    renderer_classes = [GenericJSONRenderer]
    object_label = "deposit"
    permission_classes = [IsTeller]

    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        account_number = request.query_params.get("account_number")
        if not account_number:
            return Response(
                {"error": "Account number is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            account = BankAccount.objects.get(account_number=account_number)
            serializer = CustomerInfoSerializer(account)
            return Response(serializer.data)
        except BankAccount.DoesNotExist:
            return Response(
                {"error": "Account number does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )

    @transaction.atomic
    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        account = serializer.context["account"]
        amount = serializer.validated_data["amount"]

        try:
            account.account_balance += amount
            account.full_clean()
            account.save()

            logger.info(
                f"Deposit of {amount} made to account {account.account_number} by teller "
                f"{request.user.email}"
            )

            send_deposit_email(
                user=account.user,
                user_email=account.user.email,
                amount=amount,
                currency=account.currency,
                new_balance=account.account_balance,
                account_number=account.account_number,
            )
            return Response(
                {
                    "message": f"Successfully deposited {amount} to account "
                    f"{account.account_number}",
                    "new_balance": str(account.account_balance),
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error during deposit: {str(e)}")
            return Response(
                {"error": "An error occurred during the deposit"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
            
class InitiateWithdrawalView(generics.CreateAPIView):
    serializer_class = TransactionSerializer
    renderer_classes = [GenericJSONRenderer]
    object_label = "initiate_withdrawal"

    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        account_number = request.data.get("account_number")
        amount = request.data.get("amount")

        if not account_number:
            return Response(
                {"error": "Account number is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            account = BankAccount.objects.get(
                account_number=account_number, user=request.user
            )

            if not (account.fully_activated and account.kyc_verified):
                return Response(
                    {
                        "error": "Your account is not fully verified. Please complete the "
                        "verification process"
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
        except BankAccount.DoesNotExist:
            return Response(
                {"error": "You are not authorized to withdraw from this account"},
                status=status.HTTP_403_FORBIDDEN,
            )
        serializer = self.get_serializer(
            data={
                "amount": amount,
                "description": f"Withdrawal from account {account_number}",
                "transaction_type": Transaction.TransactionType.WITHDRAWAL,
                "sender_account": account_number,
                "receiver_account": account_number,
            }
        )
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        amount = serializer.validated_data["amount"]

        if account.account_balance < amount:
            return Response(
                {"error": "Insufficient funds for withdrawal"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.session["withdrawal_data"] = {
            "account_number": account_number,
            "amount": str(amount),
        }
        logger.info("Withdrawal data stored in session")

        return Response(
            {
                "message": "Withdrawal Initiated. Please verify your username to complete the "
                "withdrawal",
                "next_step": "Verify your username to complete the withdrawal",
            },
            status=status.HTTP_200_OK,
        )

class VerifyUsernameAndWithdrawAPIView(generics.CreateAPIView):
    serializer_class = UsernameVerificationSerializer
    renderer_classes = [GenericJSONRenderer]
    object_label = "verify_username_and_withdraw"

    @transaction.atomic
    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        withdrawal_data = request.session.get("withdrawal_data")
        if not withdrawal_data:
            return Response(
                {
                    "error": "No pending withdrawal found. Please initiate a withdrawal first"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        account_number = withdrawal_data["account_number"]
        amount = Decimal(withdrawal_data["amount"])

        try:
            account = BankAccount.objects.get(
                account_number=account_number, user=request.user
            )
        except BankAccount.DoesNotExist:
            return Response(
                {"error": f"Account number {account_number} does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )
        if account.account_balance < amount:
            return Response(
                {"error": "Insufficient funds for withdrawal"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        account.account_balance -= amount
        account.save()

        withdraw_transaction = Transaction.objects.create(
            user=request.user,
            sender=request.user,
            sender_account=account,
            amount=amount,
            description=f"Withdrawal from account {account_number}",
            transaction_type=Transaction.TransactionType.WITHDRAWAL,
            status=Transaction.TransactionStatus.COMPLETED,
        )
        logger.info(f"Withdrawal of {amount} made from account {account_number}")

        send_withdrawal_email(
            user=account.user,
            user_email=account.user.email,
            amount=amount,
            currency=account.currency,
            new_balance=account.account_balance,
            account_number=account.account_number,
        )

        del request.session["withdrawal_data"]

        return Response(
            {
                "message": "Withdrawal completed successfully",
                "transaction": TransactionSerializer(withdraw_transaction).data,
            },
            status=status.HTTP_200_OK,
        )


