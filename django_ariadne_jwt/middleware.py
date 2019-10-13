"""ariadne_django_jwt middleware module"""
from django.contrib.auth import authenticate
from django.contrib.auth.models import AnonymousUser
from starlette.requests import Request as StarletteRequest
from .backends import load_backend

__all__ = ["JSONWebTokenMiddleware"]


class JSONWebTokenMiddleware(object):
    """Middleware to be used in conjuction with ariadne grapqh_* methods"""

    def resolve(self, next, root, info, **kwargs):
        """Performs the middleware relevant operations"""
        request = info.context

        token = load_backend().get_token_from_http_header(request)

        if token is not None:
            user = getattr(request, "user", None)

            if user is None or isinstance(user, AnonymousUser):
                user = authenticate(request=request, token=token)

            if user is not None:
                if isinstance(request, StarletteRequest):
                    request.scope["user"] = user
                else:
                    setattr(request, "user", user)

        return next(root, info, **kwargs)
