"""GraphQL auth backends module"""
import datetime
from django.contrib.auth import get_user_model
from django.conf import settings
from django.utils import timezone
from django.utils.module_loading import import_string
from django.utils.translation import ugettext_lazy as _
import jwt
from jwt.exceptions import DecodeError, ExpiredSignatureError
from starlette.requests import Request as StarletteRequest

from .exceptions import (
    AuthenticatedUserRequiredError,
    ExpiredTokenError,
    InvalidTokenError,
    JSONWebTokenError,
    MaximumTokenLifeReachedError,
)


def load_backend():
    return import_string(
        getattr(
            settings,
            "JWT_BACKEND",
            "django_ariadne_jwt.backends.JSONWebTokenBackend",
        )
    )()


class JSONWebTokenBackend(object):
    """Authenticates against a JSON Web Token"""

    DEFAULT_JWT_ALGORITHM = "HS256"
    ORIGINAL_IAT_CLAIM = "orig_iat"
    HTTP_AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"
    STARLETTE_HEADER = "authorization"
    AUTHORIZATION_HEADER_PREFIX = "Token"
    DEFAULT_JWT_ALGORITHM = "HS256"

    def get_token_from_http_header(self, request):
        """Retrieves the http authorization header from the request"""
        header = False
        if hasattr(request, "META"):
            header = request.META.get(self.HTTP_AUTHORIZATION_HEADER, False)
        elif isinstance(request, StarletteRequest):
            header = request.headers.get(self.STARLETTE_HEADER, False)

        if header is False:
            return None

        prefix, token = header.split()
        if prefix.lower() != self.AUTHORIZATION_HEADER_PREFIX.lower():
            return None

        return token

    def authenticate(self, request, token=None, **kwargs):
        """Performs authentication"""
        if token is None:
            return

        try:
            token_data = self.decode(token)

        except JSONWebTokenError:
            return

        return self.get_user(**self.get_user_kwargs(token_data))

    def get_user(self, user_id=None, **kwargs):
        """Gets a user from its id"""
        User = get_user_model()
        if user_id is not None:
            kwargs["pk"] = user_id

        try:
            return User.objects.get(**kwargs)

        except User.DoesNotExist:
            return None

    def get_user_kwargs(self, token_data):
        User = get_user_model()
        return {User.USERNAME_FIELD: token_data["user"]}

    def generate_token_payload(self, user, extra_payload=None):
        """Return a dictionary containing the JWT payload"""
        if extra_payload is None:
            extra_payload = {}
        expiration_delta = getattr(
            settings, "JWT_EXPIRATION_DELTA", datetime.timedelta(minutes=5)
        )

        now = timezone.localtime()

        return {
            **extra_payload,
            "user": user.username,
            "iat": int(now.timestamp()),
            "exp": int((now + expiration_delta).timestamp()),
        }

    def create(self, user, extra_payload=None):
        """Creates a JWT for an authenticated user"""
        if not user.is_authenticated:
            raise AuthenticatedUserRequiredError(
                "JWT generationr requires an authenticated user"
            )

        return jwt.encode(
            self.generate_token_payload(user, extra_payload=extra_payload),
            settings.SECRET_KEY,
            algorithm=getattr(
                settings, "JWT_ALGORITHM", self.DEFAULT_JWT_ALGORITHM
            ),
        ).decode("utf-8")

    def refresh(self, token):
        """Refreshes a JWT if possible"""
        decoded = self.decode(token)

        if self.is_token_end_of_life(decoded):
            raise MaximumTokenLifeReachedError()

        user = self.get_user(**self.get_user_kwargs(decoded))
        if user is None:
            raise InvalidTokenError(_("User not found"))

        return self.create(user, {self.ORIGINAL_IAT_CLAIM: decoded["iat"]})

    def is_token_end_of_life(self, token_data):
        return self.has_reached_end_of_life(
            token_data.get(self.ORIGINAL_IAT_CLAIM, token_data.get("iat"))
        )

    def decode(self, token):
        """Decodes a JWT"""
        try:
            decoded = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=getattr(
                    settings, "JWT_ALGORITHMS", self.DEFAULT_JWT_ALGORITHM
                ),
            )

        except ExpiredSignatureError:
            raise ExpiredTokenError()

        except DecodeError:
            raise InvalidTokenError()

        return decoded

    def has_reached_end_of_life(self, oldest_iat_claim):
        """Checks if the token has reached its end of life"""
        expiration_delta = getattr(
            settings,
            "JWT_REFRESH_EXPIRATION_DELTA",
            datetime.timedelta(days=7),
        )

        now = timezone.localtime()
        original_issue_time = timezone.make_aware(
            datetime.datetime.fromtimestamp(int(oldest_iat_claim))
        )

        end_of_life = original_issue_time + expiration_delta

        return now > end_of_life
