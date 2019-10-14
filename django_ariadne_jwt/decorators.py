"""GraphQL decorators module"""
from django.utils.translation import ugettext_lazy as _

from .exceptions import ImproperlyConfigured, LoginRequiredError


def login_required(resolver):
    """Requires login for a resolver"""

    def wrapper(parent, info, *args, **kwargs):
        if "request" not in info.context:
            raise ImproperlyConfigured(_("No request object found."))

        request = info.context["request"]
        if not hasattr(request, "user"):
            raise ImproperlyConfigured(
                _(
                    "No user found on request. Verify that "
                    "JSONWebTokenMiddleware is properly configured."
                )
            )

        user = getattr(info.context["request"], "user", None)

        if user is None or not user.is_authenticated:
            raise LoginRequiredError()

        return resolver(parent, info, *args, **kwargs)

    return wrapper
