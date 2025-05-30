from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.translation import gettext_lazy as _
from loguru import logger
from core_apps.accounts.models import BankAccount


def send_account_creation_email(user, bank_account):
    subject = _("Your New Bank Account has been Created")
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user.email]
    context = {"user": user, "account": bank_account, "site_name": settings.SITE_NAME}
    html_email = render_to_string("emails/account_created.html", context)
    plain_email = strip_tags(html_email)
    email = EmailMultiAlternatives(subject, plain_email, from_email, recipient_list)
    email.attach_alternative(html_email, "text/html")
    try:
        email.send()
        logger.info(f"Account Created email sent to: {user.email}")
    except Exception as e:
        logger.error(
            f"Failed to send account created email to {email}: Error: {str(e)}"
        )

def send_full_activation_email(account: BankAccount) -> None:
    subject = _("Your Bank Account is now fully activated")
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [account.user.email]
    context = {"account": account, "site_name": settings.SITE_NAME}
    html_email = render_to_string("emails/bank_account_activated.html", context)
    plain_email = strip_tags(html_email)
    email = EmailMultiAlternatives(subject, plain_email, from_email, recipient_list)
    email.attach_alternative(html_email, "text/html")
    try:
        email.send()
        logger.info(f"Account Fully Activated email sent to: {account.user.email}")
    except Exception as e:
        logger.error(
            f"Failed to send Fully Activated email to  {account.user.email}: Error: {str(e)}"
        )